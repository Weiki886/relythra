package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/connector/loki"
	"github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/diagnosis"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/store"
	"github.com/Weiki886/relythra/migrations"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestDiagnosisFromPersistedConnectorEvidence(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprintf("stale=%v", stale), func(t *testing.T) {
			db := openDiagnosisTestDB(t)
			ctx := context.Background()
			investigationID, serviceID := insertDiagnosisFixture(t, db)
			repository := store.NewPostgres(db)
			filter, err := redact.NewFilter()
			if err != nil {
				t.Fatal(err)
			}
			start := time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)
			metric := prometheus.Result{
				TemplateID: "prometheus.database.query_latency.v1", TemplateVersion: 1,
				QueryType: "range", Query: "private_latency_query", Unit: "seconds",
				Start: start, End: start.Add(5 * time.Minute), Step: time.Minute,
				Stale: stale, SourceReference: "https://prometheus.example.test/graph",
				Series: []prometheus.Series{{Samples: []prometheus.Sample{{Timestamp: start.Add(time.Minute), Value: 0.25}}}},
			}
			metricContext := evidence.PrometheusEvidenceContext{
				InvestigationID: investigationID, EntityType: "SERVICE", EntityID: serviceID,
				CollectedAt: start.Add(6 * time.Minute),
			}
			metricEvidence, created, err := repository.PersistPrometheusEvidence(ctx, metric, metricContext, filter)
			if err != nil || !created {
				t.Fatalf("persist metric: created=%v err=%v", created, err)
			}
			if stale && metricEvidence.Completeness != evidence.CompletenessExpired {
				t.Fatalf("stale metric completeness = %q", metricEvidence.Completeness)
			}
			logs := loki.Result{
				TemplateID: "loki.service.slow_queries.v1", TemplateVersion: 1,
				Query: `{service="checkout-api"} |= "slow"`, Direction: "backward", Limit: 100,
				Start: start, End: metric.End, SourceReference: "https://loki.example.test/loki/api/v1/query_range",
				Entries: []loki.Entry{{Timestamp: start.Add(2 * time.Minute), Line: redact.UntrustedData{
					Trust: "untrusted_data", Source: "loki", Content: "private_slow_query_log",
				}}},
			}
			logEvidence, created, err := repository.PersistLokiEvidence(ctx, logs, evidence.LokiEvidenceContext{
				InvestigationID: investigationID, EntityType: "SERVICE", EntityID: serviceID,
				CollectedAt: metricContext.CollectedAt,
			}, filter)
			if err != nil || !created {
				t.Fatalf("persist logs: created=%v err=%v", created, err)
			}

			readDiagnosis := func() investigationDiagnosis {
				t.Helper()
				response := serve(NewHandler(repository, discardLogger()), http.MethodGet,
					"/api/v1/investigations/"+investigationID+"/diagnosis")
				if response.Code != http.StatusOK {
					t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
				}
				var envelope struct {
					Data investigationDiagnosis `json:"data"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
					t.Fatal(err)
				}
				for _, private := range []string{metric.Query, "private_slow_query_log", metric.SourceReference, logs.SourceReference} {
					if strings.Contains(response.Body.String(), private) {
						t.Fatalf("diagnosis leaked %q", private)
					}
				}
				return envelope.Data
			}
			result := readDiagnosis()
			if result.InvestigationID != investigationID || result.EvidenceTotal != 2 || result.EvidenceLimit != 100 || result.EvidenceTruncated {
				t.Fatalf("snapshot metadata = %+v", result)
			}
			if stale {
				if result.Status != diagnosis.StatusInconclusive || len(result.Candidates) != 0 ||
					!slices.Contains(result.MissingRequirements, "database_latency_sample_in_window") {
					t.Fatalf("expired persisted evidence result = %+v", result)
				}
				return
			}
			if result.Status != diagnosis.StatusCandidatesFound || len(result.Candidates) != 1 {
				t.Fatalf("persisted evidence result = %+v", result)
			}
			wantIDs := []string{metricEvidence.ID, logEvidence.ID}
			slices.Sort(wantIDs)
			candidate := result.Candidates[0]
			if candidate.EntityID != serviceID || candidate.Confidence != diagnosis.ConfidenceMedium ||
				!reflect.DeepEqual(candidate.SupportEvidenceIDs, wantIDs) {
				t.Fatalf("persisted evidence candidate = %+v", candidate)
			}

			// Non-rule Evidence still counts toward the complete-snapshot cap.
			metric.TemplateID = "prometheus.service.http_latency"
			for index := 0; index < 99; index++ {
				metric.Query = fmt.Sprintf("unrelated_metric_%d", index)
				if _, created, err := repository.PersistPrometheusEvidence(ctx, metric, metricContext, filter); err != nil || !created {
					t.Fatalf("persist extra metric %d: created=%v err=%v", index, created, err)
				}
				if index == 97 {
					result = readDiagnosis()
					if result.EvidenceTotal != 100 || result.EvidenceTruncated || result.Status != diagnosis.StatusCandidatesFound ||
						len(result.Candidates) != 1 || !reflect.DeepEqual(result.Candidates[0].SupportEvidenceIDs, wantIDs) {
						t.Fatalf("exactly 100 records = %+v", result)
					}
				}
			}
			result = readDiagnosis()
			if result.EvidenceTotal != 101 || !result.EvidenceTruncated || result.Status != diagnosis.StatusInconclusive ||
				len(result.Candidates) != 0 || !reflect.DeepEqual(result.MissingRequirements, []string{"complete_evidence_snapshot"}) {
				t.Fatalf("101 records = %+v", result)
			}
		})
	}
}

func TestDiagnosisFromPersistedContainerMemoryEvidence(t *testing.T) {
	db := openDiagnosisTestDB(t)
	ctx := context.Background()
	investigationID, serviceID := insertDiagnosisFixture(t, db)
	repository := store.NewPostgres(db)
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)
	metric := prometheus.Result{
		TemplateID: "prometheus.container.memory.v1", TemplateVersion: 1,
		QueryType: "range", Query: "private_container_memory_query", Unit: "bytes",
		Start: start, End: start.Add(4 * time.Minute), Step: time.Minute,
		SourceReference: "https://prometheus.example.test/graph",
		Series: []prometheus.Series{{Labels: map[string]string{"container": "checkout-api-1"}, Samples: []prometheus.Sample{
			{Timestamp: start.Add(time.Minute), Value: 100},
			{Timestamp: start.Add(2 * time.Minute), Value: 120},
			{Timestamp: start.Add(3 * time.Minute), Value: 140},
		}}},
	}
	metricEvidence, created, err := repository.PersistPrometheusEvidence(ctx, metric, evidence.PrometheusEvidenceContext{
		InvestigationID: investigationID, EntityType: "SERVICE", EntityID: serviceID,
		CollectedAt: start.Add(5 * time.Minute),
	}, filter)
	if err != nil || !created {
		t.Fatalf("persist container memory metric: created=%v err=%v", created, err)
	}
	response := serve(NewHandler(repository, discardLogger()), http.MethodGet,
		"/api/v1/investigations/"+investigationID+"/diagnosis")
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data investigationDiagnosis `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	result := envelope.Data
	if result.RuleSetVersion != diagnosis.RuleSetVersion || result.Status != diagnosis.StatusCandidatesFound || len(result.Candidates) != 1 {
		t.Fatalf("persisted memory Evidence result = %+v", result)
	}
	candidate := result.Candidates[0]
	if candidate.RuleID != diagnosis.RuleContainerMemoryGrowth || candidate.FaultType != "CONTAINER_MEMORY_GROWTH_SIGNAL" ||
		candidate.EntityID != serviceID || candidate.Confidence != diagnosis.ConfidenceLow ||
		!reflect.DeepEqual(candidate.SupportEvidenceIDs, []string{metricEvidence.ID}) || len(candidate.ContradictEvidenceIDs) != 0 ||
		candidate.TriggerChange != "" || !slices.Contains(candidate.MissingRequirements, "memory_leak_causality_unproven") {
		t.Fatalf("persisted memory Evidence candidate exceeded its evidence: %+v", candidate)
	}
	for _, private := range []string{metric.Query, metric.SourceReference, "checkout-api-1"} {
		if strings.Contains(response.Body.String(), private) {
			t.Fatalf("diagnosis leaked %q", private)
		}
	}
}

func TestDiagnosisFromPersistedConfigurationErrorEvidence(t *testing.T) {
	db := openDiagnosisTestDB(t)
	ctx := context.Background()
	investigationID, serviceID := insertDiagnosisFixture(t, db)
	repository := store.NewPostgres(db)
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 19, 3, 0, 0, 0, time.UTC)
	logs := loki.Result{
		TemplateID: "loki.service.config_errors.v1", TemplateVersion: 1,
		Query:     `{service="checkout-api"} |~ "(?i)(invalid config|configuration error|unknown field|config[^\\n]*(invalid|error))"`,
		Direction: "backward", Limit: 100, Start: start, End: start.Add(5 * time.Minute),
		SourceReference: "https://loki.example.test/loki/api/v1/query_range",
		Entries: []loki.Entry{{Timestamp: start.Add(2 * time.Minute), Line: redact.UntrustedData{
			Trust: "untrusted_data", Source: "loki", Content: "private_configuration_error_log",
		}}},
	}
	logEvidence, created, err := repository.PersistLokiEvidence(ctx, logs, evidence.LokiEvidenceContext{
		InvestigationID: investigationID, EntityType: "SERVICE", EntityID: serviceID,
		CollectedAt: start.Add(6 * time.Minute),
	}, filter)
	if err != nil || !created {
		t.Fatalf("persist configuration error log: created=%v err=%v", created, err)
	}
	response := serve(NewHandler(repository, discardLogger()), http.MethodGet,
		"/api/v1/investigations/"+investigationID+"/diagnosis")
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data investigationDiagnosis `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	result := envelope.Data
	if result.RuleSetVersion != diagnosis.RuleSetVersion || result.Status != diagnosis.StatusCandidatesFound || len(result.Candidates) != 1 {
		t.Fatalf("persisted configuration error Evidence result = %+v", result)
	}
	candidate := result.Candidates[0]
	if candidate.RuleID != diagnosis.RuleConfigurationErrorSignal || candidate.FaultType != "CONFIGURATION_ERROR_LOG_SIGNAL" ||
		candidate.EntityID != serviceID || candidate.Confidence != diagnosis.ConfidenceLow ||
		!reflect.DeepEqual(candidate.SupportEvidenceIDs, []string{logEvidence.ID}) || len(candidate.ContradictEvidenceIDs) != 0 ||
		candidate.TriggerChange != "" || !slices.Contains(candidate.MissingRequirements, "configuration_error_causality_unproven") {
		t.Fatalf("persisted configuration error Evidence candidate exceeded its evidence: %+v", candidate)
	}
	for _, private := range []string{logs.Query, logs.SourceReference, "private_configuration_error_log"} {
		if strings.Contains(response.Body.String(), private) {
			t.Fatalf("diagnosis leaked %q", private)
		}
	}
}

func openDiagnosisTestDB(t *testing.T) *sql.DB {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("RELYTHRA_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("RELYTHRA_TEST_DATABASE_URL is not set")
	}
	testURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("relythra_diagnosis_test_%d", time.Now().UnixNano())
	if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create isolated schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := adminDB.ExecContext(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("clean isolated schema: %v", err)
		}
		_ = adminDB.Close()
	})
	query := testURL.Query()
	query.Set("search_path", schema)
	testURL.RawQuery = query.Encode()
	db, err := sql.Open("pgx", testURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.Files)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpContext(ctx, db, "."); err != nil {
		t.Fatalf("migrate isolated schema: %v", err)
	}
	return db
}

func insertDiagnosisFixture(t *testing.T, db *sql.DB) (investigationID, serviceID string) {
	t.Helper()
	ctx := context.Background()
	var projectID, incidentID string
	if err := db.QueryRowContext(ctx, `INSERT INTO projects (slug, name) VALUES ('diagnosis', 'Diagnosis') RETURNING id::text`).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO services (project_id, slug, name) VALUES ($1, 'checkout-api', 'Checkout API') RETURNING id::text`, projectID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO incidents (project_id, service_id, status, severity, summary, environment, started_at)
		VALUES ($1, $2, 'OPEN', 'ERROR', 'Checkout latency', 'prod', $3) RETURNING id::text`, projectID, serviceID,
		time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)).Scan(&incidentID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO investigations (incident_id, service_id, environment)
		VALUES ($1, $2, 'prod') RETURNING id::text`, incidentID, serviceID).Scan(&investigationID); err != nil {
		t.Fatal(err)
	}
	return investigationID, serviceID
}
