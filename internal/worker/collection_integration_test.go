package worker_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/store"
	"github.com/Weiki886/relythra/internal/worker"
	"github.com/Weiki886/relythra/migrations"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestCollectionWorkerPersistsPrometheusEvidenceBeforeCompletingPostgresJob(t *testing.T) {
	db := openCollectionIntegrationDB(t)
	ctx := context.Background()
	var projectID, serviceID string
	if err := db.QueryRowContext(ctx, `INSERT INTO projects (slug,name) VALUES ('worker-integration','Worker integration') RETURNING id::text`).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO services (project_id,slug,name) VALUES ($1,'worker-api','Worker API') RETURNING id::text`, projectID).Scan(&serviceID); err != nil {
		t.Fatalf("insert service: %v", err)
	}
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	repository := store.NewPostgres(db)
	startsAt := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	alerts, err := repository.IngestGrafanaAlerts(ctx, []store.GrafanaAlertInput{{
		ProjectSlug: "worker-integration", ServiceSlug: "worker-api", Environment: "prod",
		Fingerprint: "worker-integration-alert", FingerprintVersion: "sha256-v1", Status: "FIRING",
		Severity: "ERROR", Summary: "Worker integration alert", StartsAt: startsAt,
		Labels: json.RawMessage(`{"alertname":"WorkerIntegration"}`), Annotations: json.RawMessage(`{"summary":"bounded fixture"}`),
		RedactedPayload: json.RawMessage(`{"alerts":[]}`),
	}}, "worker-integration-delivery", filter)
	if err != nil || len(alerts) != 1 || alerts[0].InvestigationID == "" {
		t.Fatalf("ingest alert results=%+v err=%v", alerts, err)
	}
	mapping, _, err := repository.CreateDataSourceMapping(ctx, store.CreateDataSourceMappingInput{
		ProjectID: projectID, ServiceID: serviceID, Environment: "prod", SourceType: datasource.SourcePrometheus,
		PublicSettings: datasource.PublicSettings{Endpoint: "https://prometheus.example.test"},
		TemplateIDs:    []string{"prometheus.service.latency.v1"},
	})
	if err != nil {
		t.Fatalf("create Prometheus mapping: %v", err)
	}
	_ = mapping
	claimed, err := repository.ClaimInvestigationCollectionJobs(ctx, 1, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim collection job=%+v err=%v", claimed, err)
	}
	connector := &integrationPrometheusQueryer{now: time.Now}
	processor, err := worker.NewCollectionProcessor(repository, connector, collectionSecretResolverFake{}, filter, worker.CollectionOptions{})
	if err != nil {
		t.Fatalf("create CollectionProcessor: %v", err)
	}
	if err := processor.Process(ctx, claimed[0]); err != nil {
		t.Fatalf("process collection job: %v", err)
	}
	if connector.calls != 1 {
		t.Fatalf("Prometheus query count=%d, want 1", connector.calls)
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM investigation_collection_jobs WHERE id=$1`, claimed[0].ID).Scan(&status); err != nil {
		t.Fatalf("read collection status: %v", err)
	}
	if status != "COMPLETED" {
		t.Fatalf("collection status=%q, want COMPLETED", status)
	}
	timeline, err := repository.GetInvestigationTimeline(ctx, alerts[0].InvestigationID, store.InvestigationTimelineFilter{}, 20, 0)
	if err != nil {
		t.Fatalf("read persisted Evidence: %v", err)
	}
	foundPrometheus := false
	for _, item := range timeline.Items {
		if item.Evidence.SourceType == evidence.SourcePrometheus && item.Evidence.Completeness == evidence.CompletenessComplete {
			foundPrometheus = true
		}
	}
	if !foundPrometheus {
		t.Fatalf("timeline did not include completed Prometheus Evidence: %+v", timeline.Items)
	}
}

type integrationPrometheusQueryer struct {
	calls int
	now   func() time.Time
}

func (connector *integrationPrometheusQueryer) Query(_ context.Context, _ prometheusconnector.Target, query datasource.NormalizedQuery) (prometheusconnector.Result, error) {
	connector.calls++
	collected := connector.now().UTC()
	return prometheusconnector.Result{
		TemplateID: query.TemplateID, TemplateVersion: query.Version, QueryType: query.QueryType,
		Query: "registered-template-query", Unit: "seconds", Start: query.Start, End: query.End,
		Step: query.Step, Duration: time.Millisecond,
		SourceReference: "https://prometheus.example.test/api/v1/query_range",
		ResponseSHA256:  strings.Repeat("a", 64),
		Series:          []prometheusconnector.Series{{Labels: map[string]string{"route": "/checkout"}, Samples: []prometheusconnector.Sample{{Timestamp: collected.Add(-time.Minute), Value: 0.25}}}},
		LatestSampleAt:  &collected,
	}, nil
}

func openCollectionIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("RELYTHRA_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("RELYTHRA_TEST_DATABASE_URL is not set")
	}
	adminDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	t.Cleanup(func() { _ = adminDB.Close() })
	schema := fmt.Sprintf("worker_collection_test_%d", time.Now().UnixNano())
	if _, err := adminDB.ExecContext(context.Background(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}
	t.Cleanup(func() { _, _ = adminDB.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse integration database URL: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatalf("open isolated schema: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.Files)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set migration dialect: %v", err)
	}
	if err := goose.UpContext(context.Background(), db, "."); err != nil {
		t.Fatalf("migrate isolated schema: %v", err)
	}
	return db
}
