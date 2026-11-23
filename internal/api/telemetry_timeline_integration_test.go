package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	lokiconnector "github.com/Weiki886/relythra/internal/connector/loki"
	promconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/store"
)

func TestPersistedTelemetryEvidenceAppearsInInvestigationTimeline(t *testing.T) {
	db := openDiagnosisTestDB(t)
	ctx := context.Background()
	investigationID, serviceID := insertDiagnosisFixture(t, db)
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(5 * time.Minute)
	collectedAt := end.Add(time.Minute)

	metricResult := promconnector.Result{
		TemplateID: "prometheus.service.latency.v1", TemplateVersion: 1, QueryType: "range",
		Query: `histogram_quantile(0.95, sum by (le, route) (rate(demo_http_request_duration_seconds_bucket{service="checkout-api",env="prod"}[5m])))`,
		Unit:  "seconds", Start: start, End: end, Step: 30 * time.Second,
		SourceReference: "https://prometheus.example.test/graph",
		Series: []promconnector.Series{{Labels: map[string]string{"route": "/orders"}, Samples: []promconnector.Sample{
			{Timestamp: start, Value: 0.2}, {Timestamp: start.Add(time.Minute), Value: 0.8},
		}}},
	}
	logResult := lokiconnector.Result{
		TemplateID: "loki.service.slow_queries.v1", TemplateVersion: 1,
		Query: `{service="checkout-api",env="prod"} |= "slow"`, Direction: "backward", Limit: 100,
		Start: start.Add(time.Minute), End: end, SourceReference: "https://loki.example.test/loki/api/v1/query_range",
		Entries: []lokiconnector.Entry{{Timestamp: start.Add(2 * time.Minute), Line: redact.UntrustedData{
			Trust: "untrusted_data", Source: "loki", Content: "slow SQL query duration=0.8s",
		}}},
	}
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	repository := store.NewPostgres(db)
	metricEvidence, created, err := repository.PersistPrometheusEvidence(ctx, metricResult, evidence.PrometheusEvidenceContext{
		InvestigationID: investigationID, EntityType: "SERVICE", EntityID: serviceID, CollectedAt: collectedAt,
	}, filter)
	if err != nil || !created {
		t.Fatalf("persist Prometheus evidence: created=%v err=%v", created, err)
	}
	logEvidence, created, err := repository.PersistLokiEvidence(ctx, logResult, evidence.LokiEvidenceContext{
		InvestigationID: investigationID, EntityType: "SERVICE", EntityID: serviceID, CollectedAt: collectedAt,
	}, filter)
	if err != nil || !created {
		t.Fatalf("persist Loki evidence: created=%v err=%v", created, err)
	}

	response := serve(NewHandler(repository, discardLogger()), http.MethodGet, "/api/v1/investigations/"+investigationID+"/timeline")
	if response.Code != http.StatusOK {
		t.Fatalf("timeline status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data store.InvestigationTimeline `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	items := envelope.Data.Items
	if envelope.Data.Total != 2 || len(items) != 2 {
		t.Fatalf("timeline total=%d items=%+v", envelope.Data.Total, items)
	}
	if items[0].ID != metricEvidence.ID || items[0].SourceType != "PROMETHEUS" || !items[0].ObservedStart.Equal(start) {
		t.Fatalf("Prometheus timeline item = %+v", items[0])
	}
	if items[1].ID != logEvidence.ID || items[1].SourceType != "LOKI" || !items[1].ObservedStart.Equal(start.Add(time.Minute)) {
		t.Fatalf("Loki timeline item = %+v", items[1])
	}
	for _, item := range items {
		if item.EntityType != "SERVICE" || item.EntityID == nil || *item.EntityID != serviceID {
			t.Fatalf("timeline evidence owner = %s/%v, want SERVICE/%s", item.EntityType, item.EntityID, serviceID)
		}
	}
	if items[0].IndependenceGroup == "" || items[1].IndependenceGroup == "" || items[0].IndependenceGroup == items[1].IndependenceGroup {
		t.Fatalf("source independence groups = %q, %q", items[0].IndependenceGroup, items[1].IndependenceGroup)
	}
	if !strings.Contains(string(items[0].ValueSummary), "0.8") || !strings.Contains(string(items[1].ValueSummary), "slow SQL") {
		t.Fatalf("timeline summaries do not preserve connector results")
	}
}
