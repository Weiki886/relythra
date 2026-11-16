package store

import (
	"context"
	"errors"
	"testing"
	"time"

	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

func TestPersistPrometheusEvidenceValidatesOwnershipAndReplays(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "prometheus-evidence-store")
	repository := NewPostgres(db)
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	metadata := evidence.PrometheusEvidenceContext{
		InvestigationID: fixture.investigationID,
		CollectedAt:     fixture.startedAt.Add(5*time.Minute + 2*time.Second),
	}
	result := prometheusResult(fixture.startedAt)

	first, created, err := repository.PersistPrometheusEvidence(ctx, result, metadata, filter)
	if err != nil || !created {
		t.Fatalf("persist Prometheus Evidence: created=%v err=%v", created, err)
	}
	if first.SourceType != evidence.SourcePrometheus || first.EntityType != "SERVICE" || first.EntityID == nil || *first.EntityID != fixture.serviceID {
		t.Fatalf("persisted Prometheus Evidence association = %+v", first)
	}

	replayed, created, err := repository.PersistPrometheusEvidence(ctx, result, metadata, filter)
	if err != nil || created || replayed.ID != first.ID {
		t.Fatalf("replay = (%+v, created=%v, err=%v), want same immutable row", replayed, created, err)
	}

	timeline, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID,
		InvestigationTimelineFilter{SourceType: evidence.SourcePrometheus}, 10, 0)
	if err != nil {
		t.Fatalf("read Prometheus timeline: %v", err)
	}
	if timeline.Total != 1 || len(timeline.Items) != 1 || timeline.Items[0].Evidence.ID != first.ID {
		t.Fatalf("Prometheus timeline = %+v, want one persisted observation", timeline)
	}
}

func TestPersistPrometheusEvidencePreservesEmptyResultAsMissing(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "prometheus-evidence-empty")
	repository := NewPostgres(db)
	filter, _ := redact.NewFilter()
	result := prometheusResult(fixture.startedAt)
	result.Empty = true
	result.Series = nil
	result.LatestSampleAt = nil

	item, created, err := repository.PersistPrometheusEvidence(ctx, result, evidence.PrometheusEvidenceContext{
		InvestigationID: fixture.investigationID,
		CollectedAt:     fixture.startedAt.Add(5 * time.Minute),
	}, filter)
	if err != nil || !created {
		t.Fatalf("persist empty Prometheus Evidence: created=%v err=%v", created, err)
	}
	if item.Completeness != evidence.CompletenessMissing {
		t.Fatalf("empty Prometheus Evidence completeness = %q, want MISSING", item.Completeness)
	}
}

func TestPersistPrometheusEvidenceRejectsForeignInvestigationAndService(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "prometheus-evidence-owner")
	other := insertStoreFixture(t, ctx, db, "prometheus-evidence-other")
	repository := NewPostgres(db)
	filter, _ := redact.NewFilter()
	result := prometheusResult(fixture.startedAt)
	metadata := evidence.PrometheusEvidenceContext{
		InvestigationID: other.investigationID,
		CollectedAt:     fixture.startedAt.Add(5 * time.Minute),
	}
	if _, _, err := repository.PersistPrometheusEvidence(ctx, result, metadata, filter); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-Investigation persistence error = %v, want ErrNotFound", err)
	}

	metadata.InvestigationID = fixture.investigationID
	metadata.EntityID = other.serviceID
	if _, _, err := repository.PersistPrometheusEvidence(ctx, result, metadata, filter); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign service persistence error = %v, want ErrNotFound", err)
	}
	timeline, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{
		SourceType: evidence.SourcePrometheus,
	}, 10, 0)
	if err != nil {
		t.Fatalf("read timeline after rejected writes: %v", err)
	}
	if timeline.Total != 0 {
		t.Fatalf("rejected Prometheus writes persisted %d Evidence rows", timeline.Total)
	}
}

func TestPersistPrometheusEvidenceRejectsInvalidContextBeforeDatabaseAccess(t *testing.T) {
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	metadata := evidence.PrometheusEvidenceContext{
		InvestigationID: "invalid",
		CollectedAt:     start.Add(5 * time.Minute),
	}
	if _, _, err := NewPostgres(nil).PersistPrometheusEvidence(context.Background(), prometheusResult(start), metadata, filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid context error = %v, want ErrInvalidInput", err)
	}
}

func prometheusResult(start time.Time) prometheusconnector.Result {
	return prometheusconnector.Result{
		TemplateID:      "prometheus.service.http_latency",
		TemplateVersion: 1,
		QueryType:       "range",
		Query:           `histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))`,
		Unit:            "seconds",
		Start:           start,
		End:             start.Add(5 * time.Minute),
		Step:            time.Minute,
		Duration:        5 * time.Minute,
		SourceReference: "https://prometheus.example.test/graph",
		Series: []prometheusconnector.Series{{
			Labels:  map[string]string{"service": "checkout"},
			Samples: []prometheusconnector.Sample{{Timestamp: start.Add(5 * time.Minute), Value: 0.42}},
		}},
		LatestSampleAt: prometheusLatestSampleAt(start),
	}
}

func prometheusLatestSampleAt(start time.Time) *time.Time {
	value := start.Add(5 * time.Minute)
	return &value
}
