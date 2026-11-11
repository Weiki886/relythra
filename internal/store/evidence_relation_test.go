package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

func TestAddEvidenceRelationIsIdempotentAndVisibleInTimeline(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "evidence-relation-idempotency")
	filter, _ := redact.NewFilter()
	record, err := evidence.Normalize(ctx, evidence.Input{
		InvestigationID: fixture.investigationID,
		SourceType:      evidence.SourcePrometheus, EntityType: "SERVICE", EntityID: fixture.serviceID,
		ObservedStart: fixture.startedAt, ObservedEnd: fixture.startedAt.Add(time.Minute),
		CollectedAt: fixture.startedAt.Add(time.Minute), RawReference: "https://prometheus.example.test/graph",
		ValueSummary: []byte(`{"latency_ms":420}`), Completeness: evidence.CompletenessComplete,
		IndependenceGroup: "prometheus:latency",
	}, filter)
	if err != nil {
		t.Fatal(err)
	}
	repository := NewPostgres(db)
	item, created, err := repository.PersistEvidence(ctx, record)
	if err != nil || !created {
		t.Fatalf("persist evidence: created=%v err=%v", created, err)
	}
	var hypothesisID string
	if err := db.QueryRowContext(ctx, `INSERT INTO hypotheses
		(investigation_id, rank, entity, fault_type, mechanism, affected_scope, confidence, summary)
		VALUES ($1, 1, 'checkout', 'latency', 'slow query', 'checkout-api', 'LOW', 'query latency increased') RETURNING id::text`,
		fixture.investigationID).Scan(&hypothesisID); err != nil {
		t.Fatal(err)
	}
	created, err = repository.AddEvidenceRelation(ctx, fixture.investigationID, hypothesisID, item.ID, "SUPPORTS")
	if err != nil || !created {
		t.Fatalf("add first relation: created=%v err=%v", created, err)
	}
	created, err = repository.AddEvidenceRelation(ctx, fixture.investigationID, hypothesisID, item.ID, "SUPPORTS")
	if err != nil || created {
		t.Fatalf("replay relation: created=%v err=%v, want idempotent false", created, err)
	}
	created, err = repository.AddEvidenceRelation(ctx, fixture.investigationID, hypothesisID, item.ID, "CONTRADICTS")
	if err != nil || !created {
		t.Fatalf("add opposite stance: created=%v err=%v", created, err)
	}

	timeline, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{}, 20, 0)
	if err != nil || len(timeline.Items) != 1 {
		t.Fatalf("read relation timeline: timeline=%+v err=%v", timeline, err)
	}
	relations := timeline.Items[0].Relations
	if len(relations) != 2 || relations[0].HypothesisID != hypothesisID || relations[0].Stance != "CONTRADICTS" || relations[1].HypothesisID != hypothesisID || relations[1].Stance != "SUPPORTS" {
		t.Fatalf("relations = %+v", relations)
	}
}

func TestAddEvidenceRelationRejectsInvalidAndCrossInvestigationInput(t *testing.T) {
	ctx := context.Background()
	repository := NewPostgres(nil)
	if _, err := repository.AddEvidenceRelation(ctx, "bad-id", "bad-id", "bad-id", "SUPPORTS"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid IDs error = %v", err)
	}
	if _, err := repository.AddEvidenceRelation(ctx,
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333", "RELATED"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid stance error = %v", err)
	}

	db := openStoreTestDB(t)
	first := insertStoreFixture(t, ctx, db, "evidence-relation-owner")
	second := insertStoreFixture(t, ctx, db, "evidence-relation-foreign")
	item := persistRelationEvidence(t, ctx, db, first)
	hypothesisID := insertRelationHypothesis(t, ctx, db, second)
	if _, err := NewPostgres(db).AddEvidenceRelation(ctx, first.investigationID, hypothesisID, item.ID, "SUPPORTS"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-Investigation relation error = %v, want ErrNotFound", err)
	}
}

func persistRelationEvidence(t *testing.T, ctx context.Context, db *sql.DB, fixture storeFixture) Evidence {
	t.Helper()
	filter, _ := redact.NewFilter()
	record, err := evidence.Normalize(ctx, evidence.Input{
		InvestigationID: fixture.investigationID,
		SourceType:      evidence.SourceLoki, EntityType: "SERVICE", EntityID: fixture.serviceID,
		ObservedStart: fixture.startedAt, ObservedEnd: fixture.startedAt.Add(time.Minute),
		CollectedAt: fixture.startedAt.Add(time.Minute), ValueSummary: []byte(`{"errors":1}`),
		Completeness: evidence.CompletenessComplete, IndependenceGroup: "loki:errors",
	}, filter)
	if err != nil {
		t.Fatal(err)
	}
	item, created, err := NewPostgres(db).PersistEvidence(ctx, record)
	if err != nil || !created {
		t.Fatalf("persist relation evidence: created=%v err=%v", created, err)
	}
	return item
}

func insertRelationHypothesis(t *testing.T, ctx context.Context, db *sql.DB, fixture storeFixture) string {
	t.Helper()
	var id string
	if err := db.QueryRowContext(ctx, `INSERT INTO hypotheses
		(investigation_id, rank, entity, fault_type, mechanism, affected_scope, confidence, summary)
		VALUES ($1, 1, 'checkout', 'latency', 'slow query', 'checkout-api', 'LOW', 'query latency increased') RETURNING id::text`,
		fixture.investigationID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
