package runtime

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/connector/prometheus"
)

func TestOOMSummaryPreservesOverlappingWindowEstimatesAndSource(t *testing.T) {
	request := validRequest(nil)
	request.Start = request.End.Add(-time.Minute)
	zone := time.FixedZone("source", 8*60*60)
	samples := []prometheus.Sample{
		{Timestamp: request.End.In(zone), Value: 1.25},
		{Timestamp: request.Start, Value: 0},
		{Timestamp: request.Start.Add(30 * time.Second), Value: 1.25},
	}
	result := queryOOMSummary(t, request, []prometheus.Series{
		{Labels: map[string]string{"id": "cgroup-a", "host_id": "host-a"}, Samples: samples},
		metricSeries("cgroup-b", "host-a", "raw_cgroup_only", 0),
	})
	if len(result.Containers) != 2 {
		t.Fatalf("containers = %+v", result.Containers)
	}
	for _, container := range result.Containers {
		if len(container.OOMEvents.Samples) == 1 {
			if container.OOMWindowObservations == nil || len(container.OOMWindowObservations) != 0 {
				t.Fatalf("zero sample should yield empty array: %+v", container)
			}
			continue
		}
		if !reflect.DeepEqual(container.OOMEvents.Samples, samples) {
			t.Fatalf("raw measurement changed: %+v", container.OOMEvents)
		}
		observations := container.OOMWindowObservations
		if len(observations) != 2 {
			t.Fatalf("positive windows = %+v", observations)
		}
		for i, observation := range observations {
			evaluation := request.Start.Add(time.Duration(i+1) * 30 * time.Second)
			if observation.ContainerID != container.ID || observation.EstimatedOOMCount != 1.25 ||
				!observation.EvaluationTime.Equal(evaluation) || !observation.WindowStart.Equal(evaluation.Add(-5*time.Minute)) ||
				observation.SourceReference != container.OOMEvents.SourceReference || observation.EvaluationTime.Location() != time.UTC ||
				observation.WindowStart.Location() != time.UTC {
				t.Fatalf("window %d lost estimate, UTC bounds or provenance: %+v", i, observation)
			}
		}
		if len(result.Events) != 0 || container.State != "observed" {
			t.Fatalf("estimates must not become lifecycle events or change resource state: %+v", result)
		}
	}
}

func TestOOMSummaryRejectsInvalidObservationsWithoutLosingRawEvidence(t *testing.T) {
	request := validRequest(nil)
	for _, test := range []struct {
		name   string
		sample prometheus.Sample
	}{
		{"negative", prometheus.Sample{Timestamp: request.End, Value: -1}},
		{"nan", prometheus.Sample{Timestamp: request.End, Value: math.NaN()}},
		{"infinite", prometheus.Sample{Timestamp: request.End, Value: math.Inf(1)}},
		{"zero_time", prometheus.Sample{Value: 1}},
		{"before_query", prometheus.Sample{Timestamp: request.Start.Add(-time.Second), Value: 1}},
		{"after_query", prometheus.Sample{Timestamp: request.End.Add(time.Second), Value: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			series := metricSeries("cgroup-a", "host-a", "raw_cgroup_only", 0)
			series.Samples = []prometheus.Sample{test.sample}
			result := queryOOMSummary(t, request, []prometheus.Series{series})
			container := result.Containers[0]
			if len(container.OOMWindowObservations) != 0 || len(container.OOMEvents.Samples) != 1 ||
				!result.Partial || !containsGap(result.Gaps, "container_oom_window_samples_invalid") {
				t.Fatalf("unsafe summary or missing gap/raw evidence: %+v", result)
			}
		})
	}
}

func TestOOMSummaryMissingMetricsStayUnknownAndMarshalEmptyArray(t *testing.T) {
	result := queryOOMSummary(t, validRequest(nil), nil)
	container := result.Containers[0]
	if !container.OOMEvents.Empty || len(container.OOMWindowObservations) != 0 || !containsGap(result.Gaps, "container_oom_events_missing") {
		t.Fatalf("missing OOM evidence = %+v", result)
	}
	encoded, err := json.Marshal(container)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["oom_window_observations"]) != "[]" {
		t.Fatalf("empty summary JSON = %s", encoded)
	}
}

func queryOOMSummary(t *testing.T, request Request, oom []prometheus.Series) Result {
	t.Helper()
	metrics := &fakeMetrics{series: map[string][]prometheus.Series{
		"prometheus.runtime.container.cpu.v1":        {metricSeries("cgroup-a", "host-a", "raw_cgroup_only", 1)},
		"prometheus.runtime.container.memory.v1":     {metricSeries("cgroup-a", "host-a", "raw_cgroup_only", 4096)},
		"prometheus.runtime.container.start_time.v1": {metricSeries("cgroup-a", "host-a", "raw_cgroup_only", 1793772000)},
		"prometheus.runtime.container.oom_events.v1": oom,
	}}
	collector, err := NewCollector(metrics, &fakeLogs{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := collector.Query(context.Background(), Target{}, request)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestOOMSummaryRequiresSourceReference(t *testing.T) {
	request := validRequest(nil)
	result := Result{}
	containers := collectContainers(request, map[string]prometheus.Result{
		"prometheus.runtime.container.oom_events.v1": {
			Series: []prometheus.Series{metricSeries("cgroup-a", "host-a", "raw_cgroup_only", 1)},
		},
	}, &result)
	if len(containers) != 1 || len(containers[0].OOMWindowObservations) != 0 ||
		!containsGap(result.Gaps, "container_oom_window_source_missing") || !result.Partial {
		t.Fatalf("untraceable estimate: containers=%+v gaps=%v", containers, result.Gaps)
	}
}
