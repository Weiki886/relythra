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
			ID: "opaque-cgroup", HostID: "host-1", MappingStatus: "raw_cgroup_only", State: "unknown",
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

func TestRuntimeContainerReplacementHistorySurvivesPersistenceAndTimeline(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "runtime-container-replacement-history")
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	repository := NewPostgres(db)
	queryStart := fixture.startedAt.UTC()
	source := "https://prometheus.example.test/api/v1/query_range"
	empty := runtimeconnector.Measurement{Empty: true}

	for _, incarnation := range []struct {
		id         string
		instance   string
		queryStart time.Time
		startedAt  time.Time
	}{
		{
			id: "opaque-old-container", instance: "old-incarnation", queryStart: queryStart,
			startedAt: queryStart.Add(-time.Hour),
		},
		{
			id: "opaque-new-container", instance: "new-incarnation", queryStart: queryStart.Add(10 * time.Minute),
			startedAt: queryStart.Add(9 * time.Minute),
		},
	} {
		start := incarnation.queryStart
		end := start.Add(5 * time.Minute)
		evaluation := end.Add(-time.Minute)
		result := runtimeconnector.Result{
			Runtime: datasource.RuntimeDockerCompose, Service: "checkout", Environment: "demo", HostID: "host-1",
			MappingVersion: 7, Start: start, End: end,
			Containers: []runtimeconnector.Container{{
				ID: incarnation.id, InstanceID: incarnation.instance, HostID: "host-1", Service: "checkout",
				MappingStatus: "explicit_mapping", MappingVersion: 7, StartTime: &incarnation.startedAt,
				StartEvidence: runtimeconnector.Measurement{
					Samples: []prometheus.Sample{{Timestamp: evaluation, Value: float64(incarnation.startedAt.Unix())}}, SourceReference: source,
				},
				CPU: runtimeconnector.Measurement{
					Samples: []prometheus.Sample{{Timestamp: evaluation, Value: 0.25}}, SourceReference: source,
				},
				Memory: runtimeconnector.Measurement{
					Samples: []prometheus.Sample{{Timestamp: evaluation, Value: 1024}}, SourceReference: source,
				},
				OOMEvents: empty, State: "observed", LastObservedAt: &evaluation, PeerContainerIDs: []string{},
			}},
		}
		metadata := evidence.RuntimeEvidenceContext{
			InvestigationID: fixture.investigationID, CollectedAt: end.Add(time.Second),
		}
		records, err := evidence.FromRuntimeResult(ctx, result, metadata, filter)
		if err != nil {
			t.Fatalf("normalize %s runtime evidence: %v", incarnation.id, err)
		}
		items, created, err := repository.PersistEvidenceBatch(ctx, records)
		if err != nil || len(items) != 8 || len(created) != 8 {
			t.Fatalf("persist %s runtime evidence: items=%d created=%v err=%v", incarnation.id, len(items), created, err)
		}
		for i, wasCreated := range created {
			if !wasCreated {
				t.Fatalf("first persist of %s evidence item %d was not created", incarnation.id, i)
			}
		}

		metadata.CollectedAt = metadata.CollectedAt.Add(time.Hour)
		replay, err := evidence.FromRuntimeResult(ctx, result, metadata, filter)
		if err != nil {
			t.Fatalf("normalize replay for %s: %v", incarnation.id, err)
		}
		replayed, created, err := repository.PersistEvidenceBatch(ctx, replay)
		if err != nil || len(replayed) != len(items) || len(created) != len(items) {
			t.Fatalf("replay %s runtime evidence: items=%d created=%v err=%v", incarnation.id, len(replayed), created, err)
		}
		for i := range items {
			if created[i] || replayed[i].ID != items[i].ID {
				t.Fatalf("replay changed %s evidence item %d identity", incarnation.id, i)
			}
		}
	}

	timeline, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{}, 20, 0)
	if err != nil {
		t.Fatalf("read runtime timeline: %v", err)
	}
	if timeline.Total != 16 || len(timeline.Items) != 16 {
		t.Fatalf("runtime timeline has total=%d items=%d, want two batches of eight records", timeline.Total, len(timeline.Items))
	}

	for _, incarnation := range []struct {
		id         string
		instance   string
		queryStart time.Time
		startedAt  time.Time
	}{
		{
			id: "opaque-old-container", instance: "old-incarnation", queryStart: queryStart,
			startedAt: queryStart.Add(-time.Hour),
		},
		{
			id: "opaque-new-container", instance: "new-incarnation", queryStart: queryStart.Add(10 * time.Minute),
			startedAt: queryStart.Add(9 * time.Minute),
		},
	} {
		filtered, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{
			ContainerID: incarnation.id,
		}, 20, 0)
		if err != nil {
			t.Fatalf("filter timeline for %s: %v", incarnation.id, err)
		}
		if filtered.Total != 4 || len(filtered.Items) != 4 {
			t.Fatalf("timeline filter for %s returned total=%d items=%d, want four", incarnation.id, filtered.Total, len(filtered.Items))
		}
		for _, item := range filtered.Items {
			if !item.ObservedStart.Equal(incarnation.queryStart) || !item.ObservedEnd.Equal(incarnation.queryStart.Add(5*time.Minute)) {
				t.Fatalf("timeline filter for %s included another incarnation's interval: %s-%s", incarnation.id, item.ObservedStart, item.ObservedEnd)
			}
		}

		matchedRecords := 0
		startTimeRecords := 0
		for _, item := range timeline.Items {
			var summary struct {
				Measurements []struct {
					EntityType string     `json:"entity_type"`
					EntityID   string     `json:"entity_id"`
					InstanceID string     `json:"instance_id"`
					StartTime  *time.Time `json:"start_time"`
				} `json:"measurements"`
			}
			var parameters struct {
				TemplateID string `json:"template_id"`
			}
			if !item.ObservedStart.Equal(incarnation.queryStart) || !item.ObservedEnd.Equal(incarnation.queryStart.Add(5*time.Minute)) {
				continue
			}
			if err := json.Unmarshal(item.ValueSummary, &summary); err != nil {
				t.Fatalf("decode runtime timeline evidence: %v", err)
			}
			if err := json.Unmarshal(item.QueryParameters, &parameters); err != nil {
				t.Fatalf("decode runtime timeline query parameters: %v", err)
			}
			for _, measurement := range summary.Measurements {
				if measurement.EntityType != "CONTAINER" || measurement.EntityID != incarnation.id {
					continue
				}
				matchedRecords++
				if item.EntityType != "HOST" || item.EntityID == nil || *item.EntityID != "host-1" {
					t.Fatalf("runtime evidence top-level identity changed unexpectedly: %+v", item)
				}
				if measurement.InstanceID != incarnation.instance {
					t.Fatalf("timeline for %s lost incarnation identity: %s", incarnation.id, item.ValueSummary)
				}
				if parameters.TemplateID == "prometheus.runtime.container.start_time.v1" {
					startTimeRecords++
					if measurement.StartTime == nil || !measurement.StartTime.Equal(incarnation.startedAt) {
						t.Fatalf("timeline for %s lost its start time: %s", incarnation.id, item.ValueSummary)
					}
				} else if measurement.StartTime != nil {
					t.Fatalf("timeline for %s attributed start time to %s: %s", incarnation.id, parameters.TemplateID, item.ValueSummary)
				}
			}
		}
		if matchedRecords != 4 {
			t.Fatalf("timeline for %s has %d matching container records, want four", incarnation.id, matchedRecords)
		}
		if startTimeRecords != 1 {
			t.Fatalf("timeline for %s has %d start-time records, want 1", incarnation.id, startTimeRecords)
		}
	}
}
