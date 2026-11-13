package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/connector/prometheus"
	runtimeconnector "github.com/Weiki886/relythra/internal/connector/runtime"
	"github.com/Weiki886/relythra/internal/security/redact"
)

func runtimeOOMObservation() (runtimeconnector.Result, RuntimeEvidenceContext) {
	result, meta := runtimeObservation()
	container := &result.Containers[0]
	container.OOMEvents.Samples = []prometheus.Sample{
		{Timestamp: result.Start.Add(time.Minute), Value: 1.25},
		{Timestamp: result.Start.Add(2 * time.Minute), Value: 2.5},
	}
	for _, sample := range container.OOMEvents.Samples {
		container.OOMWindowObservations = append(container.OOMWindowObservations, runtimeconnector.OOMWindowObservation{
			ContainerID: container.ID, WindowStart: sample.Timestamp.Add(-5 * time.Minute),
			EvaluationTime: sample.Timestamp, EstimatedOOMCount: sample.Value, SourceReference: container.OOMEvents.SourceReference,
		})
	}
	return result, meta
}

func oomEvidenceRecord(t *testing.T, records []Record) Record {
	t.Helper()
	for _, record := range records {
		var parameters runtimeQueryParameters
		if err := json.Unmarshal(record.QueryParameters, &parameters); err != nil {
			t.Fatal(err)
		}
		if parameters.TemplateID == "prometheus.runtime.container.oom_events.v1" {
			return record
		}
	}
	t.Fatal("OOM evidence missing")
	return Record{}
}

func TestFromRuntimePreservesOOMWindowsWithoutIndependentEvents(t *testing.T) {
	result, meta := runtimeOOMObservation()
	// A rolling window may precede both the request and the latest incarnation.
	started := result.Start.Add(30 * time.Second)
	result.Containers[0].StartTime = &started
	before, _ := json.Marshal(result)
	filter, _ := redact.NewFilter()
	records, err := FromRuntimeResult(context.Background(), result, meta, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 8 {
		t.Fatalf("derived windows created extra votes: %d", len(records))
	}
	record := oomEvidenceRecord(t, records)
	var summary struct {
		Windows      []runtimeconnector.OOMWindowObservation `json:"oom_window_observations"`
		Events       []runtimeconnector.Event                `json:"events"`
		Measurements []runtimeMeasurementObservation         `json:"measurements"`
	}
	if err := json.Unmarshal(record.ValueSummary, &summary); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(summary.Windows, result.Containers[0].OOMWindowObservations) {
		t.Fatalf("lost or changed overlapping estimates: %s", record.ValueSummary)
	}
	if len(summary.Events) != 0 || len(summary.Measurements) != 1 ||
		!reflect.DeepEqual(summary.Measurements[0].Measurement.Samples, result.Containers[0].OOMEvents.Samples) ||
		record.IndependenceGroup != "prometheus:prometheus.runtime.container.oom_events.v1:v1" ||
		!strings.Contains(string(record.QueryParameters), `"time_basis":"query_evaluation_time"`) {
		t.Fatalf("derived windows changed raw data or independence: %+v", record)
	}
	for _, other := range records {
		if other.ContentHash != record.ContentHash && strings.Contains(string(other.ValueSummary), "oom_window_observations") {
			t.Fatalf("windows leaked into another template: %s", other.QueryParameters)
		}
	}
	var fields map[string]json.RawMessage
	windows, _ := json.Marshal(summary.Windows[0])
	_ = json.Unmarshal(windows, &fields)
	if _, exists := fields["instance_id"]; exists {
		t.Fatal("window incorrectly assigned to an incarnation")
	}
	after, _ := json.Marshal(result)
	if string(before) != string(after) {
		t.Fatal("adapter mutated connector result")
	}
}

func TestFromRuntimeOOMWindowsCanonicalReplayAndRedaction(t *testing.T) {
	result, meta := runtimeOOMObservation()
	filter, _ := redact.NewFilter("window-source-secret")
	reference := "https://prometheus.example.test/window-source-secret"
	result.Containers[0].OOMEvents.SourceReference = reference
	for i := range result.Containers[0].OOMWindowObservations {
		result.Containers[0].OOMWindowObservations[i].SourceReference = reference
	}
	first, err := FromRuntimeResult(context.Background(), result, meta, filter)
	if err != nil {
		t.Fatal(err)
	}
	record := oomEvidenceRecord(t, first)
	if strings.Contains(string(record.ValueSummary), "window-source-secret") {
		t.Fatal("window source was not redacted")
	}
	windows := result.Containers[0].OOMWindowObservations
	windows[0], windows[1] = windows[1], windows[0]
	zone := time.FixedZone("source", 8*60*60)
	for i := range windows {
		windows[i].EvaluationTime = windows[i].EvaluationTime.In(zone)
		windows[i].WindowStart = windows[i].WindowStart.In(zone)
	}
	result.Containers[0].OOMEvents.Samples[0], result.Containers[0].OOMEvents.Samples[1] = result.Containers[0].OOMEvents.Samples[1], result.Containers[0].OOMEvents.Samples[0]
	meta.CollectedAt = meta.CollectedAt.Add(time.Minute)
	replay, err := FromRuntimeResult(context.Background(), result, meta, filter)
	if err != nil {
		t.Fatal(err)
	}
	if record.ContentHash != oomEvidenceRecord(t, replay).ContentHash {
		t.Fatal("ordering/timezone changed replay identity")
	}
}

func TestFromRuntimeRejectsUnsupportedOOMWindowsAtomically(t *testing.T) {
	cases := map[string]func(*runtimeconnector.Result){
		"wrong container": func(r *runtimeconnector.Result) { r.Containers[0].OOMWindowObservations[0].ContainerID = "other" },
		"wrong source": func(r *runtimeconnector.Result) {
			r.Containers[0].OOMWindowObservations[0].SourceReference = "https://other.test"
		},
		"empty source": func(r *runtimeconnector.Result) { r.Containers[0].OOMWindowObservations[0].SourceReference = "" },
		"wrong window": func(r *runtimeconnector.Result) { r.Containers[0].OOMWindowObservations[0].WindowStart = r.Start },
		"zero time": func(r *runtimeconnector.Result) {
			r.Containers[0].OOMWindowObservations[0].EvaluationTime = time.Time{}
		},
		"unknown sample": func(r *runtimeconnector.Result) {
			r.Containers[0].OOMWindowObservations[0].EvaluationTime = r.Start.Add(3 * time.Minute)
			r.Containers[0].OOMWindowObservations[0].WindowStart = r.Start.Add(-2 * time.Minute)
		},
		"zero count":     func(r *runtimeconnector.Result) { r.Containers[0].OOMWindowObservations[0].EstimatedOOMCount = 0 },
		"negative count": func(r *runtimeconnector.Result) { r.Containers[0].OOMWindowObservations[0].EstimatedOOMCount = -1 },
		"nan count": func(r *runtimeconnector.Result) {
			r.Containers[0].OOMWindowObservations[0].EstimatedOOMCount = math.NaN()
		},
		"infinite count": func(r *runtimeconnector.Result) {
			r.Containers[0].OOMWindowObservations[0].EstimatedOOMCount = math.Inf(1)
		},
		"changed estimate": func(r *runtimeconnector.Result) { r.Containers[0].OOMWindowObservations[0].EstimatedOOMCount = 1 },
		"duplicate amplification": func(r *runtimeconnector.Result) {
			r.Containers[0].OOMWindowObservations = append(r.Containers[0].OOMWindowObservations, r.Containers[0].OOMWindowObservations[0])
		},
		"out of range": func(r *runtimeconnector.Result) {
			sample := &r.Containers[0].OOMEvents.Samples[0]
			sample.Timestamp = r.Start.Add(-time.Second)
			window := &r.Containers[0].OOMWindowObservations[0]
			window.EvaluationTime = sample.Timestamp
			window.WindowStart = sample.Timestamp.Add(-5 * time.Minute)
		},
	}
	filter, _ := redact.NewFilter()
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			result, meta := runtimeOOMObservation()
			mutate(&result)
			records, err := FromRuntimeResult(context.Background(), result, meta, filter)
			if !errors.Is(err, ErrInvalidInput) || records != nil {
				t.Fatalf("persisted unsupported windows: records=%d err=%v", len(records), err)
			}
		})
	}
}

func TestFromRuntimeOOMWindowsEmptyCompatibility(t *testing.T) {
	result, meta := runtimeOOMObservation()
	result.Containers[0].OOMWindowObservations = nil
	filter, _ := redact.NewFilter()
	first, err := FromRuntimeResult(context.Background(), result, meta, filter)
	if err != nil {
		t.Fatal(err)
	}
	result.Containers[0].OOMWindowObservations = []runtimeconnector.OOMWindowObservation{}
	second, err := FromRuntimeResult(context.Background(), result, meta, filter)
	if err != nil {
		t.Fatal(err)
	}
	a, b := oomEvidenceRecord(t, first), oomEvidenceRecord(t, second)
	if a.ContentHash != b.ContentHash || strings.Contains(string(a.ValueSummary), "oom_window_observations") {
		t.Fatal("empty summaries changed legacy shape/hash or fabricated windows")
	}
}

func TestFromRuntimeOOMWindowsAcrossContainersAndIntervalBoundaries(t *testing.T) {
	result, meta := runtimeOOMObservation()
	for i, timestamp := range []time.Time{result.Start, result.End} {
		result.Containers[0].OOMEvents.Samples[i].Timestamp = timestamp
		result.Containers[0].OOMWindowObservations[i].EvaluationTime = timestamp
		result.Containers[0].OOMWindowObservations[i].WindowStart = timestamp.Add(-5 * time.Minute)
	}
	second := result.Containers[0]
	second.ID = "second-cgroup"
	second.OOMWindowObservations = append([]runtimeconnector.OOMWindowObservation(nil), second.OOMWindowObservations...)
	for i := range second.OOMWindowObservations {
		second.OOMWindowObservations[i].ContainerID = second.ID
	}
	result.Containers = append(result.Containers, second)
	filter, _ := redact.NewFilter()
	first, err := FromRuntimeResult(context.Background(), result, meta, filter)
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Windows []runtimeconnector.OOMWindowObservation `json:"oom_window_observations"`
	}
	if err := json.Unmarshal(oomEvidenceRecord(t, first).ValueSummary, &summary); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, window := range summary.Windows {
		counts[window.ContainerID]++
	}
	if len(summary.Windows) != 4 || counts[result.Containers[0].ID] != 2 || counts[second.ID] != 2 {
		t.Fatalf("lost container ownership: %+v", summary.Windows)
	}
	result.Containers[0], result.Containers[1] = result.Containers[1], result.Containers[0]
	replay, err := FromRuntimeResult(context.Background(), result, meta, filter)
	if err != nil {
		t.Fatal(err)
	}
	if oomEvidenceRecord(t, first).ContentHash != oomEvidenceRecord(t, replay).ContentHash {
		t.Fatal("container ordering changed replay identity")
	}
}
