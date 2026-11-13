package store

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/connector/prometheus"
	runtimeconnector "github.com/Weiki886/relythra/internal/connector/runtime"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

func TestRuntimeOOMWindowsSurvivePersistenceReplayAndTimeline(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "runtime-oom-windows")
	start := fixture.startedAt.UTC()
	evaluation := start.Add(time.Minute)
	source := "https://prometheus.example.test/api/v1/query_range"
	windows := []runtimeconnector.OOMWindowObservation{{
		ContainerID: "opaque-cgroup", WindowStart: evaluation.Add(-5 * time.Minute),
		EvaluationTime: evaluation, EstimatedOOMCount: 1.25, SourceReference: source,
	}}
	empty := runtimeconnector.Measurement{Empty: true}
	result := runtimeconnector.Result{
		Runtime: datasource.RuntimeDockerCompose, Service: "checkout", Environment: "demo", HostID: "host-1",
		Start: start, End: start.Add(5 * time.Minute),
		Containers: []runtimeconnector.Container{{
			ID: "opaque-cgroup", HostID: "host-1", MappingStatus: "raw_cgroup_only",
			CPU: empty, Memory: empty, StartEvidence: empty,
			OOMEvents: runtimeconnector.Measurement{
				Samples: []prometheus.Sample{{Timestamp: evaluation, Value: 1.25}}, SourceReference: source,
			},
			OOMWindowObservations: windows,
		}},
	}
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	metadata := evidence.RuntimeEvidenceContext{InvestigationID: fixture.investigationID, CollectedAt: result.End.Add(time.Second)}
	records, err := evidence.FromRuntimeResult(ctx, result, metadata, filter)
	if err != nil {
		t.Fatal(err)
	}
	repository := NewPostgres(db)
	first, created, err := repository.PersistEvidenceBatch(ctx, records)
	if err != nil || len(first) != 8 || len(created) != 8 {
		t.Fatalf("persist runtime evidence: items=%d created=%v err=%v", len(first), created, err)
	}
	for i := range first {
		if !created[i] {
			t.Fatalf("first batch item %d already existed", i)
		}
	}
	metadata.CollectedAt = metadata.CollectedAt.Add(time.Hour)
	replayed, err := evidence.FromRuntimeResult(ctx, result, metadata, filter)
	if err != nil {
		t.Fatal(err)
	}
	second, created, err := repository.PersistEvidenceBatch(ctx, replayed)
	if err != nil || len(second) != len(first) || len(created) != len(first) {
		t.Fatalf("replay runtime evidence: items=%d created=%v err=%v", len(second), created, err)
	}
	for i := range first {
		if created[i] || second[i].ID != first[i].ID {
			t.Fatalf("replay item %d changed identity or inserted a duplicate", i)
		}
	}
	timeline, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{}, 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if timeline.Total != 8 || len(timeline.Items) != 8 {
		t.Fatalf("unexpected timeline size: total=%d items=%d", timeline.Total, len(timeline.Items))
	}
	found := false
	for _, item := range timeline.Items {
		var parameters struct {
			TemplateID string `json:"template_id"`
		}
		if err := json.Unmarshal(item.QueryParameters, &parameters); err != nil {
			t.Fatal(err)
		}
		if parameters.TemplateID != "prometheus.runtime.container.oom_events.v1" {
			continue
		}
		found = true
		var summary struct {
			Windows []runtimeconnector.OOMWindowObservation `json:"oom_window_observations"`
		}
		if err := json.Unmarshal(item.ValueSummary, &summary); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(summary.Windows, windows) {
			t.Fatalf("timeline lost fractional estimates or provenance: %s", item.ValueSummary)
		}
		matched := false
		for i, record := range records {
			if first[i].ID != item.ID {
				continue
			}
			matched = true
			if item.ContentHash != record.ContentHash || !sameJSONObject(item.ValueSummary, record.ValueSummary) {
				t.Fatal("timeline changed normalized summary or persisted identity")
			}
		}
		if !matched {
			t.Fatal("timeline returned an unrecognized evidence ID")
		}
	}
	if !found {
		t.Fatal("OOM evidence absent from timeline")
	}
}
