package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/connector/prometheus"
	runtimeconnector "github.com/Weiki886/relythra/internal/connector/runtime"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

func TestPersistRuntimeEvidenceValidatesOwnershipReplaysAndReadsTimeline(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "runtime-evidence-store")
	repository := NewPostgres(db)
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	result := storeRuntimeObservation(fixture)
	metadata := runtimeEvidencePersistenceContext(fixture)

	first, created, err := repository.PersistRuntimeEvidence(ctx, result, metadata, filter)
	if err != nil {
		t.Fatalf("persist runtime Evidence: %v", err)
	}
	if len(first) != 8 || len(created) != 8 {
		t.Fatalf("persisted runtime batch lengths = %d/%d, want 8/8", len(first), len(created))
	}
	for index, item := range first {
		if !created[index] || item.SourceType != evidence.SourceRuntime || item.EntityType != "HOST" ||
			item.EntityID == nil || *item.EntityID != result.HostID {
			t.Fatalf("first runtime record %d = %+v, created=%v", index, item, created[index])
		}
	}

	metadata.CollectedAt = metadata.CollectedAt.Add(time.Hour)
	replayed, created, err := repository.PersistRuntimeEvidence(ctx, result, metadata, filter)
	if err != nil || len(replayed) != len(first) || len(created) != len(first) {
		t.Fatalf("replay runtime Evidence: records=%d created=%v err=%v", len(replayed), created, err)
	}
	for index := range first {
		if created[index] || replayed[index].ID != first[index].ID {
			t.Fatalf("replay record %d changed identity or inserted a duplicate", index)
		}
	}

	timeline, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID,
		InvestigationTimelineFilter{SourceType: evidence.SourceRuntime}, 20, 0)
	if err != nil {
		t.Fatalf("read runtime timeline: %v", err)
	}
	if timeline.Total != 8 || len(timeline.Items) != 8 {
		t.Fatalf("runtime timeline = %d/%d, want 8/8", timeline.Total, len(timeline.Items))
	}
}

func TestPersistRuntimeEvidenceRejectsForeignInvestigationAndServiceWithoutWriting(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "runtime-evidence-owner")
	other := insertStoreFixture(t, ctx, db, "runtime-evidence-other")
	repository := NewPostgres(db)
	filter, _ := redact.NewFilter()
	result := storeRuntimeObservation(fixture)
	metadata := runtimeEvidencePersistenceContext(fixture)

	metadata.InvestigationID = other.investigationID
	if _, _, err := repository.PersistRuntimeEvidence(ctx, result, metadata, filter); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-Investigation persistence error = %v, want ErrNotFound", err)
	}
	metadata.InvestigationID = fixture.investigationID
	metadata.ServiceID = other.serviceID
	if _, _, err := repository.PersistRuntimeEvidence(ctx, result, metadata, filter); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign service persistence error = %v, want ErrNotFound", err)
	}

	timeline, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{
		SourceType: evidence.SourceRuntime,
	}, 20, 0)
	if err != nil {
		t.Fatalf("read timeline after rejected writes: %v", err)
	}
	if timeline.Total != 0 {
		t.Fatalf("rejected runtime writes persisted %d Evidence rows", timeline.Total)
	}
}

func TestPersistRuntimeEvidenceRejectsInvalidContextBeforeDatabaseAccess(t *testing.T) {
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	result := runtimeconnector.Result{}
	metadata := RuntimeEvidencePersistenceContext{
		InvestigationID: "invalid",
		ServiceID:       "55555555-5555-4555-8555-555555555555",
		CollectedAt:     time.Date(2026, 11, 9, 1, 6, 0, 0, time.UTC),
	}
	if _, _, err := NewPostgres(nil).PersistRuntimeEvidence(context.Background(), result, metadata, filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid context error = %v, want ErrInvalidInput", err)
	}
	metadata.InvestigationID = "11111111-1111-4111-8111-111111111111"
	metadata.ServiceID = ""
	if _, _, err := NewPostgres(nil).PersistRuntimeEvidence(context.Background(), result, metadata, filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing service identity error = %v, want ErrInvalidInput", err)
	}
}

func TestPersistRuntimeEvidenceRollsBackWhenToolCallBelongsToAnotherInvestigation(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "runtime-evidence-tool-owner")
	other := insertStoreFixture(t, ctx, db, "runtime-evidence-tool-foreign")
	var foreignToolCallID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO tool_calls (investigation_id, tool_name)
		VALUES ($1, 'query_runtime_templates') RETURNING id::text
	`, other.investigationID).Scan(&foreignToolCallID); err != nil {
		t.Fatalf("insert foreign ToolCall: %v", err)
	}

	filter, _ := redact.NewFilter()
	metadata := runtimeEvidencePersistenceContext(fixture)
	metadata.ToolCallID = foreignToolCallID
	if _, _, err := NewPostgres(db).PersistRuntimeEvidence(ctx, storeRuntimeObservation(fixture), metadata, filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("foreign ToolCall error = %v, want ErrInvalidInput", err)
	}
	timeline, err := NewPostgres(db).GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{
		SourceType: evidence.SourceRuntime,
	}, 20, 0)
	if err != nil {
		t.Fatalf("read timeline after failed batch: %v", err)
	}
	if timeline.Total != 0 {
		t.Fatalf("failed runtime batch left %d Evidence rows", timeline.Total)
	}
}

func runtimeEvidencePersistenceContext(fixture storeFixture) RuntimeEvidencePersistenceContext {
	return RuntimeEvidencePersistenceContext{
		InvestigationID: fixture.investigationID,
		ServiceID:       fixture.serviceID,
		CollectedAt:     fixture.startedAt.Add(7 * time.Minute),
	}
}

func storeRuntimeObservation(fixture storeFixture) runtimeconnector.Result {
	start := fixture.startedAt
	evaluation := start.Add(time.Minute)
	measurement := func(value float64, reference string) runtimeconnector.Measurement {
		return runtimeconnector.Measurement{
			Samples:         []prometheus.Sample{{Timestamp: evaluation, Value: value}},
			SourceReference: reference,
			Delay:           time.Minute,
		}
	}
	startedAt := start.Add(-time.Hour)
	return runtimeconnector.Result{
		Runtime: datasource.RuntimeDockerCompose, Service: "checkout-api", Environment: "prod", HostID: "host-1",
		Start: start, End: start.Add(5 * time.Minute), Duration: time.Second,
		Hosts: []runtimeconnector.Host{{
			HostID: "host-1", Instance: "node:9100",
			CPU:             measurement(0.4, "https://prometheus.example.test/api/v1/query_range"),
			MemoryAvailable: measurement(2048, "https://prometheus.example.test/api/v1/query_range"),
			Load:            measurement(1, "https://prometheus.example.test/api/v1/query_range"),
		}},
		Containers: []runtimeconnector.Container{{
			ID: "opaque-cgroup", InstanceID: "opaque-incarnation", HostID: "host-1", Service: "checkout-api",
			MappingStatus: "raw_cgroup_only", StartTime: &startedAt,
			StartEvidence: measurement(float64(startedAt.Unix()), "https://prometheus.example.test/api/v1/query_range"),
			CPU:           measurement(0.1, "https://prometheus.example.test/api/v1/query_range"),
			Memory:        measurement(1024, "https://prometheus.example.test/api/v1/query_range"),
			OOMEvents:     measurement(0, "https://prometheus.example.test/api/v1/query_range"),
			State:         "observed", PeerContainerIDs: []string{},
		}},
		Events: []runtimeconnector.Event{{
			Timestamp: start.Add(2 * time.Minute), Classification: "unverified_log_match",
			SourceReference: "https://loki.example.test/loki/api/v1/query_range",
			Line:            redact.UntrustedData{Trust: "untrusted_data", Source: "loki", Content: "restart requested", OriginalBytes: 17},
		}},
		Gaps: []string{"container_service_mapping_unavailable", "healthy_peer_evidence_unavailable"}, Partial: true,
	}
}
