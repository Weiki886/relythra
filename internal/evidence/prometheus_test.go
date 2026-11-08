package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/security/redact"
)

func TestFromPrometheusResultNormalizesBoundedQueryEvidence(t *testing.T) {
	filter, err := redact.NewFilter("known-secret-value")
	if err != nil {
		t.Fatal(err)
	}
	result := prometheusconnector.Result{
		TemplateID:      "prometheus.service.http_latency",
		TemplateVersion: 1,
		QueryType:       "range",
		Query:           `histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{service="checkout"}[5m])) by (le))`,
		Unit:            "seconds",
		Start:           time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC),
		End:             time.Date(2026, 11, 8, 10, 5, 0, 0, time.UTC),
		Step:            time.Minute,
		SourceReference: "https://prometheus.example.test/api/v1/query_range?token=known-secret-value",
		ResponseSHA256:  strings.Repeat("a", 64),
		LatestSampleAt:  timePtr(time.Date(2026, 11, 8, 10, 5, 0, 0, time.UTC)),
		Series: []prometheusconnector.Series{{
			Labels:  map[string]string{"service": "checkout", "token": "known-secret-value"},
			Samples: []prometheusconnector.Sample{{Timestamp: time.Date(2026, 11, 8, 10, 5, 0, 0, time.UTC), Value: 0.42}},
		}},
	}
	metadata := PrometheusEvidenceContext{
		InvestigationID: investigationID,
		ToolCallID:      "55555555-5555-4555-8555-555555555555",
		EntityType:      "service",
		EntityID:        "checkout",
		CollectedAt:     time.Date(2026, 11, 8, 10, 5, 2, 0, time.UTC),
	}

	record, err := FromPrometheusResult(context.Background(), result, metadata, filter)
	if err != nil {
		t.Fatalf("adapt Prometheus result: %v", err)
	}
	if err := Validate(record); err != nil {
		t.Fatalf("adapted record is invalid: %v", err)
	}
	if record.SourceType != SourcePrometheus || record.Completeness != CompletenessComplete || record.IndependenceGroup != "prometheus:prometheus.service.http_latency:v1" {
		t.Fatalf("unexpected evidence metadata: %+v", record)
	}
	if record.FreshnessSeconds == nil || *record.FreshnessSeconds != 2 {
		t.Fatalf("freshness = %v, want 2 seconds", record.FreshnessSeconds)
	}
	var summary struct {
		Series []prometheusconnector.Series `json:"series"`
	}
	if err := json.Unmarshal(record.ValueSummary, &summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.Series) != 1 || len(summary.Series[0].Samples) != 1 || summary.Series[0].Samples[0].Value != 0.42 {
		t.Fatalf("Prometheus samples were not retained: %+v", summary)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "known-secret-value") {
		t.Fatalf("adapted evidence exposed a secret: %s", encoded)
	}
}

func TestFromPrometheusResultPreservesQueryQualityState(t *testing.T) {
	filter, _ := redact.NewFilter()
	base := validPrometheusResult()
	metadata := validPrometheusEvidenceContext()
	for _, testCase := range []struct {
		name         string
		mutate       func(*prometheusconnector.Result)
		completeness string
	}{
		{name: "partial", mutate: func(result *prometheusconnector.Result) { result.Partial = true }, completeness: CompletenessPartial},
		{name: "warning", mutate: func(result *prometheusconnector.Result) { result.Warnings = []string{"partial response"} }, completeness: CompletenessPartial},
		{name: "stale", mutate: func(result *prometheusconnector.Result) { result.Stale = true }, completeness: CompletenessExpired},
		{name: "empty", mutate: func(result *prometheusconnector.Result) { result.Empty = true; result.Series = nil }, completeness: CompletenessMissing},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result := base
			testCase.mutate(&result)
			record, err := FromPrometheusResult(context.Background(), result, metadata, filter)
			if err != nil {
				t.Fatal(err)
			}
			if record.Completeness != testCase.completeness {
				t.Fatalf("completeness = %q, want %q", record.Completeness, testCase.completeness)
			}
		})
	}
}

func TestFromPrometheusResultDoesNotEmitNegativeFreshness(t *testing.T) {
	filter, _ := redact.NewFilter()
	result := validPrometheusResult()
	result.LatestSampleAt = timePtr(time.Date(2026, 11, 8, 10, 6, 0, 0, time.UTC))
	record, err := FromPrometheusResult(context.Background(), result, validPrometheusEvidenceContext(), filter)
	if err != nil {
		t.Fatal(err)
	}
	if record.FreshnessSeconds != nil {
		t.Fatalf("future sample freshness = %d, want unknown", *record.FreshnessSeconds)
	}
}

func TestFromPrometheusResultRejectsInvalidContextAndUnboundedSummary(t *testing.T) {
	filter, _ := redact.NewFilter()
	for _, testCase := range []struct {
		name   string
		result prometheusconnector.Result
		meta   PrometheusEvidenceContext
	}{
		{name: "missing investigation", result: validPrometheusResult(), meta: func() PrometheusEvidenceContext {
			value := validPrometheusEvidenceContext()
			value.InvestigationID = ""
			return value
		}()},
		{name: "missing interval", result: func() prometheusconnector.Result {
			value := validPrometheusResult()
			value.Start = time.Time{}
			return value
		}(), meta: validPrometheusEvidenceContext()},
		{name: "summary too large", result: func() prometheusconnector.Result {
			value := validPrometheusResult()
			value.Warnings = []string{strings.Repeat("x", maxJSONBytes)}
			return value
		}(), meta: validPrometheusEvidenceContext()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := FromPrometheusResult(context.Background(), testCase.result, testCase.meta, filter)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
	if _, err := FromPrometheusResult(context.Background(), validPrometheusResult(), validPrometheusEvidenceContext(), nil); !errors.Is(err, redact.ErrUnsafeOutput) {
		t.Fatalf("nil filter error = %v, want fail-closed redaction", err)
	}
}

func validPrometheusResult() prometheusconnector.Result {
	return prometheusconnector.Result{
		TemplateID: "prometheus.service.http_latency", TemplateVersion: 1, QueryType: "range",
		Query: "sum(rate(http_requests_total[5m]))", Unit: "requests/second",
		Start: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 11, 8, 10, 5, 0, 0, time.UTC), Step: time.Minute,
		SourceReference: "https://prometheus.example.test/graph", ResponseSHA256: strings.Repeat("b", 64),
		Series: []prometheusconnector.Series{{Labels: map[string]string{"service": "checkout"}, Samples: []prometheusconnector.Sample{{Timestamp: time.Date(2026, 11, 8, 10, 5, 0, 0, time.UTC), Value: 3.5}}}},
	}
}

func validPrometheusEvidenceContext() PrometheusEvidenceContext {
	return PrometheusEvidenceContext{
		InvestigationID: investigationID,
		EntityType:      "service", EntityID: "checkout",
		CollectedAt: time.Date(2026, 11, 8, 10, 5, 2, 0, time.UTC),
	}
}

func timePtr(value time.Time) *time.Time { return &value }
