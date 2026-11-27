package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Weiki886/relythra/internal/config"
	lokiconnector "github.com/Weiki886/relythra/internal/connector/loki"
	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	runtimeconnector "github.com/Weiki886/relythra/internal/connector/runtime"
	securitylogging "github.com/Weiki886/relythra/internal/security/logging"
	"github.com/Weiki886/relythra/internal/security/outbound"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/security/secrets"
	"github.com/Weiki886/relythra/internal/store"
	"github.com/Weiki886/relythra/internal/worker"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	logger, err := securitylogging.NewDefaultLogger(os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize worker logger failed")
		os.Exit(1)
	}
	slog.SetDefault(logger)
	if err := run(); err != nil {
		slog.Error("worker stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadWorker(os.Getenv)
	if err != nil {
		return err
	}
	filter, err := redact.NewFilter(cfg.DatabaseURL.Reveal())
	if err != nil {
		return err
	}
	logger, err := securitylogging.NewDefaultLogger(os.Stderr, cfg.DatabaseURL.Reveal())
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	db, err := sql.Open("pgx", cfg.DatabaseURL.Reveal())
	if err != nil {
		return errors.New("open worker database failed")
	}
	defer db.Close()
	startupContext, cancelStartup := context.WithTimeout(context.Background(), 5*time.Second)
	err = db.PingContext(startupContext)
	cancelStartup()
	if err != nil {
		return errors.New("worker database is unavailable")
	}

	policy, err := outbound.NewPolicy(cfg.DataSourcePolicy)
	if err != nil {
		return errors.New("worker outbound policy is invalid")
	}
	resolver := secrets.NewResolver(nil, nil)
	connector, err := prometheusconnector.NewConnector(policy, resolver)
	if err != nil {
		return errors.New("initialize worker Prometheus connector failed")
	}
	lokiConnector, err := lokiconnector.NewConnector(policy, resolver, filter)
	if err != nil {
		return errors.New("initialize worker Loki connector failed")
	}
	runtimeCollector, err := runtimeconnector.NewCollector(connector, lokiConnector)
	if err != nil {
		return errors.New("initialize worker runtime collector failed")
	}
	processor, err := worker.NewCollectionProcessor(store.NewPostgres(db), connector, resolver, filter, worker.CollectionOptions{
		LokiConnector: lokiConnector, RuntimeConnector: runtimeCollector,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	heartbeat := worker.NewHeartbeat(cfg.HeartbeatInterval)
	go heartbeat.Start(ctx)
	collectionErrors := make(chan error, 1)
	go func() { collectionErrors <- processor.Run(ctx, cfg.PollInterval) }()

	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           heartbeat.MetricsHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errorChannel := make(chan error, 1)
	go func() {
		slog.Info("worker metrics listening", "address", cfg.Address)
		errorChannel <- server.ListenAndServe()
	}()

	var runErr error
	collectionStopped := false
	select {
	case <-ctx.Done():
	case err := <-errorChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
		stop()
	case err := <-collectionErrors:
		collectionStopped = true
		if err != nil {
			runErr = errors.New("worker collection loop stopped")
		}
		stop()
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownContext)
	if !collectionStopped {
		select {
		case <-collectionErrors:
		case <-shutdownContext.Done():
			if shutdownErr == nil {
				shutdownErr = shutdownContext.Err()
			}
		}
	}
	if runErr != nil {
		return runErr
	}
	return shutdownErr
}
