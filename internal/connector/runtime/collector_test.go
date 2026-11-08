package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/connector/loki"
	"github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/security/redact"
)

func TestQueryRejectsKubernetesAndMutationBeforeSourceCalls(t *testing.T) {
	metrics := &fakeMetrics{}
	logs := &fakeLogs{}
	collector, err := NewCollector(metrics, logs)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []Request{
		validRequest(func(request *Request) { request.Runtime = datasource.RuntimeKubernetes }),
		validRequest(func(request *Request) { request.Action = "restart" }),
	} {
		_, err := collector.Query(context.Background(), Target{}, query)
		if !errors.Is(err, ErrUnsupportedRuntime) && !errors.Is(err, ErrUnsupportedOperation) {
			t.Fatalf("error = %v", err)
		}
	}
	if metrics.calls != 0 || logs.calls != 0 {
		t.Fatalf("unsupported query reached sources: metrics=%d logs=%d", metrics.calls, logs.calls)
	}
}

func TestQueryKeepsContainerInstancesSeparateAndMarksUnmappedEvidence(t *testing.T) {
	metrics := &fakeMetrics{series: map[string][]prometheus.Series{
		"prometheus.runtime.container.cpu.v1": {
			metricSeries("cgroup-a", "host-a", "raw_cgroup_only", 1.5),
			metricSeries("cgroup-b", "host-a", "raw_cgroup_only", 0.25),
		},
		"prometheus.runtime.container.memory.v1": {
			metricSeries("cgroup-a", "host-a", "raw_cgroup_only", 4096),
			metricSeries("cgroup-b", "host-a", "raw_cgroup_only", 2048),
		},
		"prometheus.runtime.container.start_time.v1": {
			metricSeries("cgroup-a", "host-a", "raw_cgroup_only", 1793772000),
			metricSeries("cgroup-b", "host-a", "raw_cgroup_only", 1793772060),
		},
		"prometheus.runtime.container.oom_events.v1":  {},
		"prometheus.runtime.host.cpu.v1":              {hostSeries("host-a", 2.5)},
		"prometheus.runtime.host.memory_available.v1": {hostSeries("host-a", 8192)},
		"prometheus.runtime.host.load.v1":             {hostSeries("host-a", 0.5)},
	}}
	logs := &fakeLogs{entries: []loki.Entry{{
		Timestamp: time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC),
		Labels:    map[string]string{"service": "checkout-api", "env": "prod", "host_id": "host-a"},
		Line:      redact.UntrustedData{Content: "container restarted", Trust: "untrusted_data"},
	}}}
	collector, err := NewCollector(metrics, logs)
	if err != nil {
		t.Fatal(err)
	}
	result, err := collector.Query(context.Background(), Target{}, validRequest(nil))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(result.Containers) != 2 || result.Containers[0].ID == result.Containers[1].ID {
		t.Fatalf("container instances were merged: %+v", result.Containers)
	}
	for _, container := range result.Containers {
		if container.ID == "cgroup-a" || container.MappingStatus != "raw_cgroup_only" || container.Service != "" {
			t.Fatalf("raw cgroup was exposed or falsely mapped: %+v", container)
		}
		if container.InstanceID == "" || container.StartTime == nil || container.State != "observed" || container.Stale {
			t.Fatalf("container instance metadata missing: %+v", container)
		}
	}
	if len(result.Hosts) != 1 || result.Hosts[0].HostID != "host-a" || result.Hosts[0].CPU.Empty || result.Hosts[0].MemoryAvailable.Empty || result.Hosts[0].Load.Empty {
		t.Fatalf("host evidence = %+v", result.Hosts)
	}
	if len(result.Events) != 1 || result.Events[0].ContainerID != "" || result.Events[0].Line.Trust != "untrusted_data" || result.Events[0].Classification != "unverified_log_match" {
		t.Fatalf("event correlation or trust boundary = %+v", result.Events)
	}
	if !result.Partial || !containsGap(result.Gaps, "container_oom_events_unavailable") || !containsGap(result.Gaps, "container_service_mapping_unavailable") {
		t.Fatalf("missing evidence was not surfaced: %+v", result)
	}
}

func TestQueryRejectsInvalidWindowBeforeSourceCalls(t *testing.T) {
	metrics := &fakeMetrics{}
	logs := &fakeLogs{}
	collector, err := NewCollector(metrics, logs)
	if err != nil {
		t.Fatal(err)
	}
	query := validRequest(nil)
	query.Start = query.End.Add(-3 * time.Hour)
	if _, err := collector.Query(context.Background(), Target{}, query); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("error = %v", err)
	}
	if metrics.calls != 0 || logs.calls != 0 {
		t.Fatalf("invalid window reached sources: metrics=%d logs=%d", metrics.calls, logs.calls)
	}
}

func TestQueryRejectsInvalidServiceBeforeSourceCalls(t *testing.T) {
	metrics := &fakeMetrics{}
	logs := &fakeLogs{}
	collector, err := NewCollector(metrics, logs)
	if err != nil {
		t.Fatal(err)
	}
	query := validRequest(nil)
	query.Service = "checkout-api with spaces"
	if _, err := collector.Query(context.Background(), Target{}, query); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("error = %v", err)
	}
	if metrics.calls != 0 || logs.calls != 0 {
		t.Fatalf("invalid service reached sources: metrics=%d logs=%d", metrics.calls, logs.calls)
	}
}

func TestQueryDoesNotTrustMappedLabelsWithoutIdentityContract(t *testing.T) {
	one := metricSeries("mapped-a", "host-a", "mapped", 1)
	one.Labels["container_label_com_docker_compose_service"] = "checkout-api"
	two := metricSeries("mapped-b", "host-a", "mapped", 2)
	two.Labels["container_label_com_docker_compose_service"] = "checkout-api"
	metrics := &fakeMetrics{series: map[string][]prometheus.Series{
		"prometheus.runtime.container.cpu.v1":        {one, two},
		"prometheus.runtime.container.memory.v1":     {one, two},
		"prometheus.runtime.container.oom_events.v1": {one, two},
	}}
	collector, err := NewCollector(metrics, &fakeLogs{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := collector.Query(context.Background(), Target{}, validRequest(nil))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(result.Containers) != 2 {
		t.Fatalf("containers = %+v", result.Containers)
	}
	for _, container := range result.Containers {
		if container.MappingStatus != "raw_cgroup_only" || container.Service != "" || len(container.PeerContainerIDs) != 0 {
			t.Fatalf("mapped peer comparison = %+v", container)
		}
	}
}

type fakeMetrics struct {
	calls  int
	series map[string][]prometheus.Series
	err    error
}

func (fake *fakeMetrics) Query(_ context.Context, _ prometheus.Target, query datasource.NormalizedQuery) (prometheus.Result, error) {
	fake.calls++
	if fake.err != nil {
		return prometheus.Result{}, fake.err
	}
	series := fake.series[query.TemplateID]
	return prometheus.Result{
		TemplateID: query.TemplateID, SourceReference: "http://prometheus.example.test/graph",
		Series: series, Empty: len(series) == 0,
	}, nil
}

type fakeLogs struct {
	calls   int
	entries []loki.Entry
	err     error
}

func (fake *fakeLogs) Query(_ context.Context, _ loki.Target, query datasource.NormalizedQuery) (loki.Result, error) {
	fake.calls++
	if fake.err != nil {
		return loki.Result{}, fake.err
	}
	return loki.Result{
		TemplateID: query.TemplateID, SourceReference: "http://loki.example.test/explore",
		Entries: fake.entries, Empty: len(fake.entries) == 0,
	}, nil
}

func metricSeries(id, hostID, mappingStatus string, value float64) prometheus.Series {
	return prometheus.Series{
		Labels:  map[string]string{"id": id, "host_id": hostID, "mapping_status": mappingStatus},
		Samples: []prometheus.Sample{{Timestamp: time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC), Value: value}},
	}
}

func hostSeries(hostID string, value float64) prometheus.Series {
	return prometheus.Series{
		Labels:  map[string]string{"host_id": hostID},
		Samples: []prometheus.Sample{{Timestamp: time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC), Value: value}},
	}
}

func validRequest(mutate func(*Request)) Request {
	end := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	request := Request{
		Runtime: datasource.RuntimeDockerCompose,
		Action:  "query", Service: "checkout-api", Environment: "prod", HostID: "host-a",
		Start: end.Add(-30 * time.Minute), End: end, Step: 30 * time.Second,
	}
	if mutate != nil {
		mutate(&request)
	}
	return request
}

func containsGap(gaps []string, expected string) bool {
	for _, gap := range gaps {
		if gap == expected {
			return true
		}
	}
	return false
}

func TestQueryCancelledBeforeSources(t *testing.T) {
	metrics, logs := &fakeMetrics{}, &fakeLogs{}
	collector, _ := NewCollector(metrics, logs)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := collector.Query(ctx, Target{}, validRequest(nil))
	if !errors.Is(err, context.Canceled) || metrics.calls != 0 || logs.calls != 0 {
		t.Fatalf("cancelled query: err=%v metricCalls=%d logCalls=%d", err, metrics.calls, logs.calls)
	}
}

func TestQueryPropagatesStaleAndFutureResourceGaps(t *testing.T) {
	for _, offset := range []time.Duration{-10 * time.Minute, 2 * time.Minute} {
		t.Run(offset.String(), func(t *testing.T) {
			cpu := metricSeries("a", "host-a", "raw_cgroup_only", 1)
			cpu.Samples[0].Timestamp = cpu.Samples[0].Timestamp.Add(offset)
			memory := metricSeries("a", "host-a", "raw_cgroup_only", 1024)
			metrics := &fakeMetrics{series: map[string][]prometheus.Series{
				"prometheus.runtime.container.cpu.v1":    {cpu},
				"prometheus.runtime.container.memory.v1": {memory},
				"prometheus.runtime.host.cpu.v1":         {{Labels: map[string]string{"host_id": "host-a"}, Samples: cpu.Samples}},
			}}
			collector, _ := NewCollector(metrics, &fakeLogs{})
			result, err := collector.Query(context.Background(), Target{}, validRequest(nil))
			if err != nil {
				t.Fatal(err)
			}
			if !result.Partial || !containsGap(result.Gaps, "resource_samples_stale_or_skewed") || result.Containers[0].State == "observed" {
				t.Fatalf("invalid freshness treated as current: %+v", result)
			}
		})
	}
}

func TestQueryNeverJoinsLogContainerIDToRawCgroup(t *testing.T) {
	logs := &fakeLogs{entries: []loki.Entry{
		{Labels: map[string]string{"host_id": "host-a", "service": "checkout-api", "env": "prod", "container_id": "a"}},
		{Labels: map[string]string{"host_id": "other-host", "service": "checkout-api", "env": "prod", "container_id": "a"}},
	}}
	collector, _ := NewCollector(&fakeMetrics{}, logs)
	result, err := collector.Query(context.Background(), Target{}, validRequest(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 || result.Events[0].ContainerID != "" || !containsGap(result.Gaps, "container_lifecycle_events_unverified") {
		t.Fatalf("log match was falsely correlated: %+v", result)
	}
}

func TestQueryIdentitiesIncludeHostAndAmbiguousStartDoesNotInventInstance(t *testing.T) {
	var ids []string
	for _, host := range []string{"host-a", "host-b"} {
		resource := metricSeries("same-cgroup", host, "raw_cgroup_only", 1)
		starts := metricSeries("same-cgroup", host, "raw_cgroup_only", 1793772000)
		starts.Samples = append(starts.Samples, prometheus.Sample{Timestamp: starts.Samples[0].Timestamp.Add(-time.Minute), Value: 1793771000})
		metrics := &fakeMetrics{series: map[string][]prometheus.Series{
			"prometheus.runtime.container.cpu.v1":        {resource},
			"prometheus.runtime.container.start_time.v1": {starts},
		}}
		collector, _ := NewCollector(metrics, &fakeLogs{})
		result, err := collector.Query(context.Background(), Target{}, validRequest(func(q *Request) { q.HostID = host }))
		if err != nil {
			t.Fatal(err)
		}
		c := result.Containers[0]
		ids = append(ids, c.ID)
		if c.StartTime != nil || c.InstanceID != "" || !containsGap(result.Gaps, "container_incarnation_ambiguous") {
			t.Fatalf("ambiguous start attributed to last instance: %+v", result)
		}
	}
	if ids[0] == ids[1] {
		t.Fatal("different hosts share cgroup identity")
	}
}

func TestQueryPartialFailureStillReturnsResources(t *testing.T) {
	metrics := &fakeMetrics{series: map[string][]prometheus.Series{"prometheus.runtime.container.memory.v1": {metricSeries("a", "host-a", "raw_cgroup_only", 1024)}}}
	collector, _ := NewCollector(metrics, &fakeLogs{err: errors.New("unavailable")})
	result, err := collector.Query(context.Background(), Target{}, validRequest(nil))
	if err != nil || len(result.Containers) != 1 || result.Containers[0].Memory.Empty || !containsGap(result.Gaps, "container_lifecycle_events_unavailable") {
		t.Fatalf("partial failure: result=%+v err=%v", result, err)
	}
}

func TestQueryBoundsAggregatePointsAndOutputEntities(t *testing.T) {
	metrics, logs := &fakeMetrics{}, &fakeLogs{}
	collector, _ := NewCollector(metrics, logs)
	_, err := collector.Query(context.Background(), Target{}, validRequest(func(q *Request) { q.MaxSeries = 100; q.MaxPoints = 1000 }))
	if !errors.Is(err, ErrInvalidQuery) || metrics.calls != 0 || logs.calls != 0 {
		t.Fatalf("excessive aggregate budget: %v", err)
	}
	metrics.series = map[string][]prometheus.Series{
		"prometheus.runtime.container.cpu.v1":    {metricSeries("a", "host-a", "raw_cgroup_only", 1)},
		"prometheus.runtime.container.memory.v1": {metricSeries("b", "host-a", "raw_cgroup_only", 1)},
	}
	result, err := collector.Query(context.Background(), Target{}, validRequest(func(q *Request) { q.MaxSeries = 1 }))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Containers) > 1 || !result.Partial || !containsGap(result.Gaps, "runtime_entities_truncated") {
		t.Fatalf("entity budget not enforced: %+v", result)
	}
}

func TestQueryDuplicateSeriesNeverSelectsArbitraryValue(t *testing.T) {
	metrics := &fakeMetrics{series: map[string][]prometheus.Series{"prometheus.runtime.container.cpu.v1": {
		metricSeries("a", "host-a", "raw_cgroup_only", 1), metricSeries("a", "host-a", "raw_cgroup_only", 9),
	}}}
	collector, _ := NewCollector(metrics, &fakeLogs{})
	result, err := collector.Query(context.Background(), Target{}, validRequest(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Containers[0].CPU.Empty || !containsGap(result.Gaps, "runtime_duplicate_series") {
		t.Fatalf("arbitrary duplicate selected: %+v", result)
	}
}

func TestQueryAcceptsLegacyHostLabelButRejectsConflictingHostIdentity(t *testing.T) {
	logs := &fakeLogs{entries: []loki.Entry{
		{Timestamp: validRequest(nil).End, Labels: map[string]string{"host": "host-a", "service": "checkout-api", "env": "prod"}},
		{Labels: map[string]string{"host": "host-b", "host_id": "host-a", "service": "checkout-api", "env": "prod"}},
	}}
	collector, _ := NewCollector(&fakeMetrics{}, logs)
	result, err := collector.Query(context.Background(), Target{}, validRequest(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 || result.Events[0].ContainerID != "" || !result.Events[0].Timestamp.Equal(validRequest(nil).End) {
		t.Fatalf("legacy host identity: %+v", result.Events)
	}
}

func TestQueryDoesNotTreatRootCgroupAsContainer(t *testing.T) {
	metrics := &fakeMetrics{series: map[string][]prometheus.Series{"prometheus.runtime.container.cpu.v1": {metricSeries("/", "host-a", "raw_cgroup_only", 1)}}}
	collector, _ := NewCollector(metrics, &fakeLogs{})
	result, err := collector.Query(context.Background(), Target{}, validRequest(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Containers) != 0 || !containsGap(result.Gaps, "container_resource_metrics_missing") {
		t.Fatalf("root cgroup reported as container: %+v", result)
	}
}

func TestQueryRejectsFutureStartEvidenceForInstanceIdentity(t *testing.T) {
	resource := metricSeries("cgroup-a", "host-a", "raw_cgroup_only", 1)
	start := metricSeries("cgroup-a", "host-a", "raw_cgroup_only", 1793772000)
	start.Samples[0].Timestamp = validRequest(nil).End.Add(2 * time.Minute)
	metrics := &fakeMetrics{series: map[string][]prometheus.Series{
		"prometheus.runtime.container.cpu.v1":        {resource},
		"prometheus.runtime.container.memory.v1":     {resource},
		"prometheus.runtime.container.start_time.v1": {start},
	}}
	collector, _ := NewCollector(metrics, &fakeLogs{})
	result, err := collector.Query(context.Background(), Target{}, validRequest(nil))
	if err != nil {
		t.Fatal(err)
	}
	c := result.Containers[0]
	if c.InstanceID != "" || c.StartTime != nil || !c.ClockSkew || c.State != "unknown" || len(c.StartEvidence.Samples) != 1 {
		t.Fatalf("skewed start evidence generated instance identity: %+v", c)
	}
}

func TestQueryDisclosesExporterScrapeFreshnessIsUnknown(t *testing.T) {
	collector, _ := NewCollector(&fakeMetrics{}, &fakeLogs{})
	result, err := collector.Query(context.Background(), Target{}, validRequest(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial || !containsGap(result.Gaps, "exporter_scrape_freshness_unavailable") {
		t.Fatalf("range evaluation timestamps imply scrape freshness: %+v", result)
	}
}
