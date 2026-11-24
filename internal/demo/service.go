// Package demo implements the deliberately small, read-only demonstration workload.
package demo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Service, Project, Environment, Release, Host, Container string
	InventoryURL                                            string
	EnableFaults                                            bool
}
type StockStore interface {
	Stock(context.Context) (int, error)
	SlowQuery(context.Context) error
}
type observation struct {
	Count   uint64
	Sum     float64
	Buckets [7]uint64
}

var bounds = [...]float64{.005, .01, .025, .05, .1, .5, 1}

type telemetry struct {
	mu       sync.Mutex
	service  string
	identity Config
	requests map[string]uint64
	routes   map[string]*observation
}

func NewHandler(cfg Config, store StockStore, client *http.Client, logger *slog.Logger) (http.Handler, error) {
	if cfg.Service != "orders" && cfg.Service != "inventory" {
		return nil, errors.New("unknown demo service")
	}
	for _, label := range []string{cfg.Project, cfg.Environment, cfg.Release, cfg.Host, cfg.Container} {
		if label == "" || strings.ContainsAny(label, "\r\n") {
			return nil, errors.New("missing or invalid demo label")
		}
	}
	if cfg.Service == "inventory" && store == nil {
		return nil, errors.New("inventory requires stock store")
	}
	if cfg.Service == "orders" {
		u, err := url.Parse(cfg.InventoryURL)
		if err != nil || u.Host == "" || u.User != nil || u.Scheme != "http" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return nil, errors.New("inventory requires fixed HTTP origin")
		}
	}
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if logger == nil {
		return nil, errors.New("logger required")
	}
	logger = logger.With("project", cfg.Project, "service", cfg.Service, "env", cfg.Environment, "release", cfg.Release, "host", cfg.Host, "container", cfg.Container, "runtime_type", "docker-compose")
	metrics := &telemetry{service: cfg.Service, identity: cfg, requests: map[string]uint64{}, routes: map[string]*observation{}}
	mux := http.NewServeMux()
	fetch := func(ctx context.Context, path string) (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.InventoryURL+path, nil)
		if err != nil {
			return 0, err
		}
		res, err := client.Do(req)
		if err != nil {
			return 0, errors.New("inventory unavailable")
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return 0, errors.New("inventory unavailable")
		}
		if path == "/health/ready" {
			return 0, nil
		}
		var body struct {
			Available *int `json:"available"`
		}
		data, readErr := io.ReadAll(io.LimitReader(res.Body, 4097))
		if readErr != nil || len(data) > 4096 || json.Unmarshal(data, &body) != nil || body.Available == nil || *body.Available < 0 {
			return 0, errors.New("inventory response invalid")
		}
		return *body.Available, nil
	}
	respond := func(w http.ResponseWriter, status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var err error
		if cfg.Service == "inventory" {
			_, err = store.Stock(ctx)
		} else {
			_, err = fetch(ctx, "/health/ready")
		}
		if err != nil {
			respond(w, 503, map[string]string{"error": "dependency or demo schema unavailable"})
			return
		}
		respond(w, 200, map[string]string{"status": "ready"})
	})
	route := "/stock"
	if cfg.Service == "orders" {
		route = "/orders"
	}
	mux.HandleFunc("GET "+route, func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var quantity int
		var err error
		if cfg.Service == "inventory" {
			if cfg.EnableFaults {
				err = store.SlowQuery(ctx)
			}
			if err == nil {
				quantity, err = store.Stock(ctx)
			}
		} else {
			quantity, err = fetch(ctx, "/stock")
		}
		status := 200
		if err != nil {
			status = 503
			respond(w, status, map[string]string{"error": "dependency unavailable"})
		} else {
			respond(w, status, map[string]any{"service": cfg.Service, "available": quantity, "release": cfg.Release})
		}
		elapsed := time.Since(start).Seconds()
		metrics.record(route, status, elapsed)
		logger.Info("request completed", "route", route, "status", status, "duration_ms", elapsed*1000)
	})
	if cfg.EnableFaults && cfg.Service == "inventory" {
		mux.HandleFunc("GET /internal/test/slow-query", func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), time.Second)
			defer cancel()
			start := time.Now()
			if err := store.SlowQuery(ctx); err != nil {
				respond(w, 503, map[string]string{"error": "test query unavailable"})
				return
			}
			logger.Info("test query completed", "query_id", "demo-fixed-delay", "duration_ms", float64(time.Since(start).Microseconds())/1000)
			respond(w, 200, map[string]string{"status": "ok"})
		})
	}
	mux.HandleFunc("GET /metrics", metrics.serve)
	return mux, nil
}
func (m *telemetry) record(route string, status int, seconds float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[fmt.Sprintf("%s\x00%d", route, status)]++
	o := m.routes[route]
	if o == nil {
		o = &observation{}
		m.routes[route] = o
	}
	o.Count++
	o.Sum += seconds
	for i, b := range bounds {
		if seconds <= b {
			o.Buckets[i]++
		}
	}
}
func (m *telemetry) serve(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintln(w, "# HELP demo_service_info Explicit demo instance identity.\n# TYPE demo_service_info gauge")
	_, _ = fmt.Fprintf(w, "demo_service_info{project=%q,service=%q,env=%q,host=%q,container=%q,release=%q,runtime_type=\"docker-compose\"} 1\n", m.identity.Project, m.identity.Service, m.identity.Environment, m.identity.Host, m.identity.Container, m.identity.Release)
	_, _ = fmt.Fprintln(w, "# HELP demo_http_requests_total Completed business requests.\n# TYPE demo_http_requests_total counter")
	for key, count := range m.requests {
		parts := strings.Split(key, "\x00")
		_, _ = fmt.Fprintf(w, "demo_http_requests_total{service=%q,route=%q,status=%q} %d\n", m.service, parts[0], parts[1], count)
	}
	_, _ = fmt.Fprintln(w, "# HELP demo_http_request_duration_seconds Business request duration.\n# TYPE demo_http_request_duration_seconds histogram")
	for route, o := range m.routes {
		for i, b := range bounds {
			_, _ = fmt.Fprintf(w, "demo_http_request_duration_seconds_bucket{service=%q,route=%q,le=%q} %d\n", m.service, route, fmt.Sprint(b), o.Buckets[i])
		}
		_, _ = fmt.Fprintf(w, "demo_http_request_duration_seconds_bucket{service=%q,route=%q,le=\"+Inf\"} %d\ndemo_http_request_duration_seconds_sum{service=%q,route=%q} %g\ndemo_http_request_duration_seconds_count{service=%q,route=%q} %d\n", m.service, route, o.Count, m.service, route, o.Sum, m.service, route, o.Count)
	}
}
