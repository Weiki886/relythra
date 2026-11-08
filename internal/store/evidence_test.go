package store

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

func TestPersistEvidenceIsIdempotentAndAvailableInTimeline(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "evidence-idempotency")
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	input := evidence.Input{
		InvestigationID:   fixture.investigationID,
		SourceType:        evidence.SourcePrometheus,
		EntityType:        "service",
		EntityID:          fixture.serviceID,
		ObservedStart:     fixture.startedAt,
		ObservedEnd:       fixture.startedAt.Add(5 * time.Minute),
		CollectedAt:       fixture.startedAt.Add(5*time.Minute + 2*time.Second),
		QueryText:         "sum(rate(http_requests_total[5m]))",
		RawReference:      "https://prometheus.example.test/graph",
		QueryParameters:   json.RawMessage(`{"window":"5m"}`),
		ValueSummary:      json.RawMessage(`{"p95_ms":420}`),
		Completeness:      evidence.CompletenessExpired,
		IndependenceGroup: "prometheus:checkout-latency",
		SourceTimezone:    "+08:00",
		SourceTimeText:    "2026-11-04T13:00:00+08:00",
	}
	record, err := evidence.Normalize(ctx, input, filter)
	if err != nil {
		t.Fatalf("normalize evidence: %v", err)
	}

	repository := NewPostgres(db)
	first, created, err := repository.PersistEvidence(ctx, record)
	if err != nil || !created {
		t.Fatalf("persist first evidence: created=%v err=%v", created, err)
	}
	replay := record
	replay.CollectedAt = replay.CollectedAt.Add(24 * time.Hour)
	second, created, err := repository.PersistEvidence(ctx, replay)
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("persist replay: id=%q created=%v err=%v, want same id and created=false", second.ID, created, err)
	}
	if second.CollectedAt == nil || !second.CollectedAt.Equal(record.CollectedAt) {
		t.Fatalf("replay changed original collected_at: got %v want %s", second.CollectedAt, record.CollectedAt)
	}
	if !sameJSONObject(second.QueryParameters, record.QueryParameters) {
		t.Fatalf("query parameters = %s, want %s", second.QueryParameters, record.QueryParameters)
	}

	timeline, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{
		Completeness: evidence.CompletenessExpired,
	}, 20, 0)
	if err != nil {
		t.Fatalf("read expired evidence timeline: %v", err)
	}
	if timeline.Total != 1 || len(timeline.Items) != 1 || timeline.Items[0].ID != first.ID {
		t.Fatalf("expired evidence timeline = %+v", timeline)
	}
	if timeline.Items[0].CollectedAt == nil || !timeline.Items[0].CollectedAt.Equal(record.CollectedAt) ||
		!sameJSONObject(timeline.Items[0].QueryParameters, record.QueryParameters) {
		t.Fatalf("timeline lost persisted metadata: %+v", timeline.Items[0])
	}
}

func sameJSONObject(first, second json.RawMessage) bool {
	var firstValue any
	var secondValue any
	if json.Unmarshal(first, &firstValue) != nil || json.Unmarshal(second, &secondValue) != nil {
		return false
	}
	return reflect.DeepEqual(firstValue, secondValue)
}

func TestPersistEvidenceRejectsCrossInvestigationToolCall(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	first := insertStoreFixture(t, ctx, db, "evidence-toolcall-owner")
	second := insertStoreFixture(t, ctx, db, "evidence-toolcall-foreign")
	var toolCallID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO tool_calls (investigation_id, tool_name)
		VALUES ($1, 'query_metric_template') RETURNING id::text
	`, second.investigationID).Scan(&toolCallID); err != nil {
		t.Fatalf("insert foreign tool call: %v", err)
	}
	filter, _ := redact.NewFilter()
	record, err := evidence.Normalize(ctx, evidence.Input{
		InvestigationID:   first.investigationID,
		SourceType:        evidence.SourcePrometheus,
		EntityType:        "service",
		ObservedStart:     first.startedAt,
		ObservedEnd:       first.startedAt.Add(time.Minute),
		CollectedAt:       first.startedAt.Add(time.Minute),
		QueryText:         "up",
		RawReference:      "https://prometheus.example.test/graph",
		ValueSummary:      json.RawMessage(`{"up":1}`),
		Completeness:      evidence.CompletenessComplete,
		IndependenceGroup: "prometheus:up",
	}, filter)
	if err != nil {
		t.Fatalf("normalize evidence: %v", err)
	}
	repository := NewPostgres(db)
	if _, created, err := repository.PersistEvidence(ctx, record); err != nil || !created {
		t.Fatalf("persist initial evidence: created=%v err=%v", created, err)
	}
	record.ToolCallID = &toolCallID
	if _, _, err := repository.PersistEvidence(ctx, record); err == nil {
		t.Fatal("persist accepted a ToolCall owned by another Investigation")
	}
}
