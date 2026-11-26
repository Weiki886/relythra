package worker_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/store"
	"github.com/Weiki886/relythra/internal/worker"
)

func TestCollectionWorkerLokiPostgresRetryPreservesEvidenceAndCompletesLease(t *testing.T) {
	db := openCollectionIntegrationDB(t)
	ctx := context.Background()
	var projectID, serviceID string
	if err := db.QueryRowContext(ctx, `INSERT INTO projects (slug,name) VALUES ('worker-loki','Worker Loki') RETURNING id::text`).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO services (project_id,slug,name) VALUES ($1,'worker-api','Worker API') RETURNING id::text`, projectID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	filter, _ := redact.NewFilter()
	repository := store.NewPostgres(db)
	now := time.Now().UTC().Truncate(time.Second)
	alerts, err := repository.IngestGrafanaAlerts(ctx, []store.GrafanaAlertInput{{
		ProjectSlug: "worker-loki", ServiceSlug: "worker-api", Environment: "prod",
		Fingerprint: "worker-loki-alert", FingerprintVersion: "sha256-v1", Status: "FIRING",
		Severity: "ERROR", Summary: "Worker Loki integration", StartsAt: now.Add(-10 * time.Minute),
		Labels: json.RawMessage(`{"alertname":"WorkerLoki"}`), Annotations: json.RawMessage(`{}`),
		RedactedPayload: json.RawMessage(`{"alerts":[]}`),
	}}, "worker-loki-delivery", filter)
	if err != nil || len(alerts) != 1 || alerts[0].InvestigationID == "" {
		t.Fatalf("alerts=%+v err=%v", alerts, err)
	}
	for source, templateID := range map[datasource.SourceType]string{
		datasource.SourceLoki:       "loki.service.slow_queries.v1",
		datasource.SourcePrometheus: "prometheus.service.latency.v1",
	} {
		_, _, err := repository.CreateDataSourceMapping(ctx, store.CreateDataSourceMappingInput{
			ProjectID: projectID, ServiceID: serviceID, Environment: "prod", SourceType: source,
			PublicSettings: datasource.PublicSettings{Endpoint: "https://observability.example.test"}, TemplateIDs: []string{templateID},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	lokiResult := validCollectionLokiResult(t)
	lokiResult.Entries[0].Timestamp = now.Add(-time.Minute)
	lokiConnector := &collectionLokiFake{result: lokiResult}
	prometheusConnector := &collectionPrometheusFake{result: validCollectionPrometheusResult(), err: &prometheusconnector.QueryError{Category: prometheusconnector.ErrorTimeout}}
	processor, err := worker.NewCollectionProcessor(repository, prometheusConnector, collectionSecretResolverFake{}, filter, worker.CollectionOptions{
		Now: func() time.Time { return now }, RetryDelay: func(int) time.Duration { return 0 }, LokiConnector: lokiConnector,
	})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		jobs, err := repository.ClaimInvestigationCollectionJobs(ctx, 1, time.Minute)
		if err != nil || len(jobs) != 1 {
			t.Fatalf("claim attempt=%d jobs=%+v err=%v", attempt, jobs, err)
		}
		err = processor.Process(ctx, jobs[0])
		var status string
		if readErr := db.QueryRowContext(ctx, `SELECT status FROM investigation_collection_jobs WHERE id=$1`, jobs[0].ID).Scan(&status); readErr != nil {
			t.Fatal(readErr)
		}
		if attempt == 0 {
			if err == nil || status != "PENDING" {
				t.Fatalf("first attempt err=%v status=%s", err, status)
			}
			prometheusConnector.err = nil
		} else if err != nil || status != "COMPLETED" {
			t.Fatalf("recovery err=%v status=%s", err, status)
		}
		timeline, readErr := repository.GetInvestigationTimeline(ctx, alerts[0].InvestigationID, store.InvestigationTimelineFilter{}, 20, 0)
		if readErr != nil {
			t.Fatal(readErr)
		}
		lokiEvidence := 0
		for _, item := range timeline.Items {
			if item.Evidence.SourceType == evidence.SourceLoki && item.Evidence.Completeness == evidence.CompletenessComplete {
				lokiEvidence++
				if item.Evidence.EntityID == nil || *item.Evidence.EntityID != serviceID || item.Evidence.InvestigationID != alerts[0].InvestigationID {
					t.Fatalf("wrong Loki ownership=%+v", item.Evidence)
				}
			}
		}
		if lokiEvidence != 1 {
			t.Fatalf("attempt=%d Loki evidence=%d, want one immutable snapshot across retries", attempt, lokiEvidence)
		}
	}
	if len(lokiConnector.calls) != 2 {
		t.Fatalf("Loki calls=%d, want both collection attempts", len(lokiConnector.calls))
	}
}
