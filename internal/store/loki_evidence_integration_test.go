package store

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/connector/loki"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

func TestPersistLokiEvidenceValidatesOwnershipReplaysAndReadsTimeline(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "loki-evidence-store")
	repository := NewPostgres(db)
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	result, metadata := storeLokiObservation(fixture)

	first, created, err := repository.PersistLokiEvidence(ctx, result, metadata, filter)
	if err != nil || !created {
		t.Fatalf("persist Loki Evidence: created=%v err=%v", created, err)
	}
	if first.SourceType != evidence.SourceLoki || first.EntityType != "SERVICE" || first.EntityID == nil || *first.EntityID != fixture.serviceID {
		t.Fatalf("persisted Loki Evidence association = %+v", first)
	}

	replayed, created, err := repository.PersistLokiEvidence(ctx, result, metadata, filter)
	if err != nil || created || replayed.ID != first.ID {
		t.Fatalf("replay = (%+v, created=%v, err=%v), want same immutable row", replayed, created, err)
	}

	timeline, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID,
		InvestigationTimelineFilter{SourceType: evidence.SourceLoki}, 10, 0)
	if err != nil {
		t.Fatalf("read Loki timeline: %v", err)
	}
	if timeline.Total != 1 || len(timeline.Items) != 1 || timeline.Items[0].Evidence.ID != first.ID {
		t.Fatalf("Loki timeline = %+v, want one persisted observation", timeline)
	}
	if timeline.Items[0].QueryText != first.QueryText || timeline.Items[0].RawReference != first.RawReference ||
		timeline.Items[0].Completeness != evidence.CompletenessComplete {
		t.Fatalf("Loki timeline lost query metadata: %+v", timeline.Items[0])
	}
}

func TestPersistLokiEvidenceRejectsForeignInvestigationAndServiceWithoutWriting(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "loki-evidence-owner")
	other := insertStoreFixture(t, ctx, db, "loki-evidence-other")
	repository := NewPostgres(db)
	filter, _ := redact.NewFilter()
	result, metadata := storeLokiObservation(fixture)

	metadata.InvestigationID = other.investigationID
	if _, _, err := repository.PersistLokiEvidence(ctx, result, metadata, filter); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-Investigation persistence error = %v, want ErrNotFound", err)
	}
	metadata.InvestigationID = fixture.investigationID
	metadata.EntityID = other.serviceID
	if _, _, err := repository.PersistLokiEvidence(ctx, result, metadata, filter); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign service persistence error = %v, want ErrNotFound", err)
	}

	timeline, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{
		SourceType: evidence.SourceLoki,
	}, 10, 0)
	if err != nil {
		t.Fatalf("read timeline after rejected writes: %v", err)
	}
	if timeline.Total != 0 {
		t.Fatalf("rejected Loki writes persisted %d Evidence rows", timeline.Total)
	}
}

func TestPersistLokiEvidenceRejectsInvalidContextBeforeDatabaseAccess(t *testing.T) {
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	result := loki.Result{}
	metadata := evidence.LokiEvidenceContext{
		InvestigationID: "invalid",
		EntityType:      "SERVICE",
		EntityID:        "55555555-5555-4555-8555-555555555555",
		CollectedAt:     time.Date(2026, 11, 9, 1, 6, 0, 0, time.UTC),
	}
	if _, _, err := NewPostgres(nil).PersistLokiEvidence(context.Background(), result, metadata, filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid context error = %v, want ErrInvalidInput", err)
	}
	metadata.InvestigationID = "11111111-1111-4111-8111-111111111111"
	metadata.EntityID = ""
	if _, _, err := NewPostgres(nil).PersistLokiEvidence(context.Background(), result, metadata, filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing service identity error = %v, want ErrInvalidInput", err)
	}
}

func TestPersistLokiEvidencePreservesEmptyAndPartialPageCompleteness(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "loki-evidence-page-status")
	repository := NewPostgres(db)
	filter, _ := redact.NewFilter()

	for _, tc := range []struct {
		name   string
		mutate func(*loki.Result)
		want   string
	}{
		{name: "empty", mutate: func(result *loki.Result) { result.Entries = nil; result.Empty = true }, want: evidence.CompletenessMissing},
		{name: "partial page", mutate: func(result *loki.Result) {
			result.Entries = nil
			result.Empty = true
			result.NextCursor = "opaque-cursor"
		}, want: evidence.CompletenessPartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, metadata := storeLokiObservation(fixture)
			tc.mutate(&result)
			item, created, err := repository.PersistLokiEvidence(ctx, result, metadata, filter)
			if err != nil || !created {
				t.Fatalf("persist %s page: created=%v err=%v", tc.name, created, err)
			}
			if item.Completeness != tc.want {
				t.Fatalf("%s page completeness = %q, want %q", tc.name, item.Completeness, tc.want)
			}
			if strings.Contains(string(item.ValueSummary), "opaque-cursor") {
				t.Fatal("opaque Loki cursor was persisted")
			}
		})
	}
}

func storeLokiObservation(fixture storeFixture) (loki.Result, evidence.LokiEvidenceContext) {
	start := fixture.startedAt.Add(time.Minute)
	entry := loki.Entry{
		Timestamp:       start.Add(time.Minute + 123*time.Nanosecond),
		SourceTimestamp: strconv.FormatInt(start.Add(time.Minute+123*time.Nanosecond).UnixNano(), 10),
		Labels:          map[string]string{"service": "checkout-api"},
		Line: redact.UntrustedData{
			Trust: "untrusted_data", Source: "loki", Content: "slow SQL", OriginalBytes: 8,
		},
	}
	return loki.Result{
			TemplateID: "loki.service.slow_queries.v1", TemplateVersion: 1,
			Query: `{service="checkout-api",environment="prod"} |= "slow"`,
			Start: start, End: start.Add(5 * time.Minute), Direction: "backward", Severity: "error", Limit: 100,
			SourceReference: "https://loki.example.test/loki/api/v1/query_range", ResponseSHA256: strings.Repeat("a", 64),
			Entries: []loki.Entry{entry},
		}, evidence.LokiEvidenceContext{
			InvestigationID: fixture.investigationID,
			EntityType:      "SERVICE",
			EntityID:        fixture.serviceID,
			CollectedAt:     start.Add(6 * time.Minute),
		}
}
