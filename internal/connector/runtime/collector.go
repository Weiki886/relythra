// Package runtime combines bounded Prometheus and Loki observations for a
// Docker Compose runtime without using Docker's management API.
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/connector/loki"
	"github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/security/redact"
)

const (
	DefaultMaxSeries = 10
	DefaultMaxPoints = 240
	MaxSeries        = 100
	MaxPoints        = 1000
	MaxQueryWindow   = 2 * time.Hour
	maxIdentityBytes = 4096
)

var (
	ErrInvalidQuery         = errors.New("invalid runtime query")
	ErrUnsupportedRuntime   = errors.New("runtime is not supported")
	ErrUnsupportedOperation = errors.New("runtime operation is not supported")
	hostIDPattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
)

type MetricsClient interface {
	Query(context.Context, prometheus.Target, datasource.NormalizedQuery) (prometheus.Result, error)
}

type LogsClient interface {
	Query(context.Context, loki.Target, datasource.NormalizedQuery) (loki.Result, error)
}

type Target struct {
	Prometheus prometheus.Target
	Loki       loki.Target
}

type Request struct {
	Runtime           datasource.RuntimeType
	Action            string
	Service           string
	Environment       string
	HostID            string
	MappingVersion    int
	ContainerMappings []datasource.RuntimeContainerMapping
	Start             time.Time
	End               time.Time
	Step              time.Duration
	MaxSeries         int
	MaxPoints         int
	MaxLogLines       int
}

// Measurement timestamps are query evaluation times. Delay and Stale describe
// the returned evaluation coverage, not exporter scrape age or runtime health.
type Measurement struct {
	Samples         []prometheus.Sample `json:"samples"`
	SourceReference string              `json:"source_reference,omitempty"`
	Delay           time.Duration       `json:"delay"`
	Empty           bool                `json:"empty"`
	Stale           bool                `json:"stale"`
	Partial         bool                `json:"partial"`
}

type Host struct {
	HostID          string      `json:"host_id"`
	Instance        string      `json:"instance,omitempty"`
	CPU             Measurement `json:"cpu"`
	MemoryAvailable Measurement `json:"memory_available"`
	Load            Measurement `json:"load"`
	LastObservedAt  *time.Time  `json:"last_observed_at,omitempty"`
	ClockSkew       bool        `json:"clock_skew"`
}

type Container struct {
	ID               string      `json:"id"`
	InstanceID       string      `json:"instance_id"`
	HostID           string      `json:"host_id"`
	Service          string      `json:"service,omitempty"`
	MappingStatus    string      `json:"mapping_status"`
	MappingVersion   int         `json:"mapping_version,omitempty"`
	StartTime        *time.Time  `json:"start_time,omitempty"`
	StartEvidence    Measurement `json:"start_evidence"`
	CPU              Measurement `json:"cpu"`
	Memory           Measurement `json:"memory"`
	OOMEvents        Measurement `json:"oom_events"`
	LastObservedAt   *time.Time  `json:"last_observed_at,omitempty"`
	Stale            bool        `json:"stale"`
	ClockSkew        bool        `json:"clock_skew"`
	State            string      `json:"state"`
	PeerContainerIDs []string    `json:"peer_container_ids"`
}

type Event struct {
	Timestamp         time.Time            `json:"timestamp"`
	ContainerID       string               `json:"container_id,omitempty"`
	Classification    string               `json:"classification"`
	OutsideTimeWindow bool                 `json:"outside_time_window,omitempty"`
	SourceReference   string               `json:"source_reference,omitempty"`
	Line              redact.UntrustedData `json:"line"`
}

type Result struct {
	Runtime        datasource.RuntimeType `json:"runtime"`
	Service        string                 `json:"service"`
	Environment    string                 `json:"environment"`
	HostID         string                 `json:"host_id"`
	MappingVersion int                    `json:"mapping_version,omitempty"`
	Start          time.Time              `json:"start"`
	End            time.Time              `json:"end"`
	Duration       time.Duration          `json:"duration"`
	Hosts          []Host                 `json:"hosts"`
	Containers     []Container            `json:"containers"`
	Events         []Event                `json:"events"`
	Gaps           []string               `json:"gaps"`
	Partial        bool                   `json:"partial"`
}

type Collector struct {
	metrics MetricsClient
	logs    LogsClient
}

func NewCollector(metrics MetricsClient, logs LogsClient) (*Collector, error) {
	if metrics == nil || logs == nil {
		return nil, errors.New("Prometheus and Loki clients are required")
	}
	return &Collector{metrics: metrics, logs: logs}, nil
}

func (collector *Collector) Query(ctx context.Context, target Target, request Request) (Result, error) {
	started := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	if collector == nil || collector.metrics == nil || collector.logs == nil {
		return Result{}, fmt.Errorf("%w: collector is not configured", ErrInvalidQuery)
	}
	if request.Runtime != datasource.RuntimeDockerCompose {
		return Result{}, ErrUnsupportedRuntime
	}
	if request.Action == "" {
		request.Action = "query"
	}
	if request.Action != "query" {
		return Result{}, ErrUnsupportedOperation
	}
	request, err := normalizeRequest(request)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidQuery, err)
	}
	logQuery, err := normalizedLogQuery(request)
	if err != nil {
		return Result{}, fmt.Errorf("%w: lifecycle query normalization failed", ErrInvalidQuery)
	}
	result := Result{
		Runtime: request.Runtime, Service: request.Service, Environment: request.Environment, HostID: request.HostID,
		MappingVersion: request.MappingVersion,
		Start:          request.Start, End: request.End,
		Hosts: []Host{}, Containers: []Container{}, Events: []Event{}, Gaps: []string{},
	}

	metricResults := make(map[string]prometheus.Result, 7)
	for _, specification := range runtimeMetricTemplates {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		service := "runtime"
		if strings.HasPrefix(specification.id, "prometheus.runtime.host.") {
			service = "host"
		}
		query, queryErr := normalizedMetricQuery(specification.id, service, request)
		if queryErr != nil {
			return Result{}, fmt.Errorf("%w: metric query normalization failed", ErrInvalidQuery)
		}
		metricResult, queryErr := collector.metrics.Query(ctx, target.Prometheus, query)
		if queryErr != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return Result{}, contextErr
			}
			result.Partial = true
			result.Gaps = append(result.Gaps, specification.gap)
			continue
		}
		metricResult.Series = rejectDuplicateSeries(metricResult.Series, &result)
		metricResults[specification.id] = metricResult
		if metricResult.Partial || metricResult.Stale || metricResult.Empty {
			result.Partial = true
		}
		if metricResult.Empty {
			result.Gaps = append(result.Gaps, specification.gap)
		}
	}

	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	result.Hosts = collectHosts(request, metricResults, &result)
	result.Containers = collectContainers(request, metricResults, &result)
	if len(result.Containers) > request.MaxSeries {
		result.Containers = result.Containers[:request.MaxSeries]
		result.Gaps = append(result.Gaps, "runtime_entities_truncated")
		result.Partial = true
	}
	if len(result.Hosts) > request.MaxSeries {
		result.Hosts = result.Hosts[:request.MaxSeries]
		result.Gaps = append(result.Gaps, "runtime_entities_truncated")
		result.Partial = true
	}

	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	logResult, err := collector.logs.Query(ctx, target.Loki, logQuery)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return Result{}, contextErr
		}
		result.Partial = true
		result.Gaps = append(result.Gaps, "container_lifecycle_events_unavailable")
	} else {
		result.Events = normalizeEvents(logResult, request)
		result.Partial = true
		result.Gaps = append(result.Gaps, "container_lifecycle_events_unverified")
		if logResult.Partial || logResult.TimeSkew || logResult.Empty {
			result.Partial = true
		}
		if logResult.Empty {
			result.Gaps = append(result.Gaps, "container_lifecycle_events_missing")
		}
	}
	if len(result.Hosts) == 0 {
		result.Gaps = append(result.Gaps, "host_resource_metrics_missing")
		result.Partial = true
	}
	if len(result.Containers) == 0 {
		result.Gaps = append(result.Gaps, "container_resource_metrics_missing")
		result.Partial = true
	}
	unmappedContainers := false
	for _, container := range result.Containers {
		unmappedContainers = unmappedContainers || container.MappingStatus != "explicit_mapping"
	}
	if unmappedContainers {
		result.Gaps = append(result.Gaps, "container_service_mapping_unavailable")
		result.Partial = true
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	result.Partial = true
	result.Gaps = append(result.Gaps, "healthy_peer_evidence_unavailable", "exporter_scrape_freshness_unavailable")
	sort.Strings(result.Gaps)
	result.Gaps = compactGaps(result.Gaps)
	result.Duration = time.Since(started)
	return result, nil
}

type metricTemplate struct{ id, gap string }

var runtimeMetricTemplates = []metricTemplate{
	{id: "prometheus.runtime.container.cpu.v1", gap: "container_cpu_metrics_unavailable"},
	{id: "prometheus.runtime.container.memory.v1", gap: "container_memory_metrics_unavailable"},
	{id: "prometheus.runtime.container.oom_events.v1", gap: "container_oom_events_unavailable"},
	{id: "prometheus.runtime.container.start_time.v1", gap: "container_start_time_unavailable"},
	{id: "prometheus.runtime.host.cpu.v1", gap: "host_cpu_metrics_unavailable"},
	{id: "prometheus.runtime.host.memory_available.v1", gap: "host_memory_metrics_unavailable"},
	{id: "prometheus.runtime.host.load.v1", gap: "host_load_metrics_unavailable"},
}

func normalizeRequest(request Request) (Request, error) {
	if !hostIDPattern.MatchString(request.HostID) {
		return Request{}, errors.New("host ID is invalid")
	}
	if request.MappingVersion < 0 ||
		(len(request.ContainerMappings) > 0 && request.MappingVersion < 1) ||
		len(datasource.ValidateRuntimeContainerMappings(request.ContainerMappings)) > 0 {
		return Request{}, errors.New("runtime container mappings or version are invalid")
	}
	if request.Start.IsZero() || request.End.IsZero() || !request.End.After(request.Start) || request.End.Sub(request.Start) > MaxQueryWindow {
		return Request{}, errors.New("time window must be positive and no longer than two hours")
	}
	request.Start = request.Start.UTC()
	request.End = request.End.UTC()
	if request.Step == 0 {
		request.Step = 30 * time.Second
	}
	if request.MaxSeries == 0 {
		request.MaxSeries = DefaultMaxSeries
	}
	if request.MaxPoints == 0 {
		request.MaxPoints = DefaultMaxPoints
	}
	if request.MaxLogLines == 0 {
		request.MaxLogLines = 100
	}
	if request.MaxSeries < 1 || request.MaxSeries > MaxSeries || request.MaxPoints < 2 || request.MaxPoints > MaxPoints ||
		len(runtimeMetricTemplates)*request.MaxSeries*request.MaxPoints > datasource.MaxQueryTotalPoints || request.MaxLogLines < 1 || request.MaxLogLines > datasource.MaxQueryLimit {
		return Request{}, errors.New("runtime query budget is out of range")
	}
	return request, nil
}

func normalizedMetricQuery(templateID, selectorService string, request Request) (datasource.NormalizedQuery, error) {
	templates, issues := datasource.ResolveTemplates(datasource.SourcePrometheus, []string{templateID})
	if len(issues) != 0 || len(templates) != 1 {
		return datasource.NormalizedQuery{}, errors.New("runtime metric template is not registered")
	}
	query, issues := datasource.ValidateQuery(templates[0], datasource.QueryParameters{
		Service: selectorService, Environment: request.Environment,
		Start: request.Start.Format(time.RFC3339Nano), End: request.End.Format(time.RFC3339Nano),
		Step: request.Step.String(), MaxSeries: request.MaxSeries, MaxPoints: request.MaxPoints,
	})
	if len(issues) != 0 {
		return datasource.NormalizedQuery{}, errors.New("runtime metric query is invalid")
	}
	return query, nil
}

func normalizedLogQuery(request Request) (datasource.NormalizedQuery, error) {
	templates, issues := datasource.ResolveTemplates(datasource.SourceLoki, []string{"loki.container.restarts.v1"})
	if len(issues) != 0 || len(templates) != 1 {
		return datasource.NormalizedQuery{}, errors.New("runtime lifecycle template is not registered")
	}
	query, issues := datasource.ValidateQuery(templates[0], datasource.QueryParameters{
		Service: request.Service, Environment: request.Environment,
		Direction: "backward", Start: request.Start.Format(time.RFC3339Nano), End: request.End.Format(time.RFC3339Nano),
		Limit: request.MaxLogLines,
	})
	if len(issues) != 0 {
		return datasource.NormalizedQuery{}, errors.New("runtime lifecycle query is invalid")
	}
	return query, nil
}

func collectHosts(request Request, results map[string]prometheus.Result, result *Result) []Host {
	types := []struct {
		id  string
		set func(*Host, Measurement)
	}{
		{"prometheus.runtime.host.cpu.v1", func(host *Host, value Measurement) { host.CPU = value }},
		{"prometheus.runtime.host.memory_available.v1", func(host *Host, value Measurement) { host.MemoryAvailable = value }},
		{"prometheus.runtime.host.load.v1", func(host *Host, value Measurement) { host.Load = value }},
	}
	hosts := make(map[string]*Host)
	for _, metricType := range types {
		metricResult, exists := results[metricType.id]
		if !exists {
			continue
		}
		for _, series := range metricResult.Series {
			hostID := series.Labels["host_id"]
			if hostID != request.HostID {
				continue
			}
			instance := series.Labels["instance"]
			key := hostID + "\x00" + instance
			host := hosts[key]
			if host == nil {
				host = &Host{
					HostID: hostID, Instance: instance,
					CPU: emptyMeasurement(), MemoryAvailable: emptyMeasurement(), Load: emptyMeasurement(),
				}
				hosts[key] = host
			}
			measurement := makeMeasurement(series.Samples, metricResult.SourceReference, metricResult.Partial, request)
			metricType.set(host, measurement)
			updateLatest(&host.LastObservedAt, series.Samples)
			host.ClockSkew = host.ClockSkew || hasFutureSample(series.Samples, request.End)
		}
	}
	ordered := make([]Host, 0, len(hosts))
	for _, host := range hosts {
		if host.CPU.Empty {
			result.Gaps = append(result.Gaps, "host_cpu_metrics_missing")
			result.Partial = true
		}
		if host.MemoryAvailable.Empty {
			result.Gaps = append(result.Gaps, "host_memory_metrics_missing")
			result.Partial = true
		}
		if host.Load.Empty {
			result.Gaps = append(result.Gaps, "host_load_metrics_missing")
			result.Partial = true
		}
		if measurementIncomplete(host.CPU) || measurementIncomplete(host.MemoryAvailable) || measurementIncomplete(host.Load) || host.ClockSkew {
			result.Partial = true
			result.Gaps = append(result.Gaps, "resource_samples_stale_or_skewed")
		}
		ordered = append(ordered, *host)
	}
	sort.Slice(ordered, func(left, right int) bool {
		if ordered[left].HostID == ordered[right].HostID {
			return ordered[left].Instance < ordered[right].Instance
		}
		return ordered[left].HostID < ordered[right].HostID
	})
	return ordered
}

func collectContainers(request Request, results map[string]prometheus.Result, result *Result) []Container {
	types := []struct {
		id  string
		set func(*Container, Measurement)
	}{
		{"prometheus.runtime.container.cpu.v1", func(container *Container, value Measurement) { container.CPU = value }},
		{"prometheus.runtime.container.memory.v1", func(container *Container, value Measurement) { container.Memory = value }},
		{"prometheus.runtime.container.oom_events.v1", func(container *Container, value Measurement) { container.OOMEvents = value }},
	}
	containers := make(map[string]*Container)
	explicitMappings := make(map[string]struct{}, len(request.ContainerMappings))
	for _, mapping := range request.ContainerMappings {
		explicitMappings[mapping.CgroupID+"\x00"+mapping.HostID] = struct{}{}
	}
	for _, metricType := range types {
		metricResult, exists := results[metricType.id]
		if !exists {
			continue
		}
		for _, series := range metricResult.Series {
			rawID := series.Labels["id"]
			hostID := series.Labels["host_id"]
			if rawID == "" || rawID == "/" || len(rawID) > maxIdentityBytes || hostID != request.HostID {
				continue
			}
			key := rawID + "\x00" + hostID
			container := containers[key]
			if container == nil {
				mappingStatus, service, mappingVersion := "raw_cgroup_only", "", 0
				if _, mapped := explicitMappings[rawID+"\x00"+hostID]; mapped {
					mappingStatus, service, mappingVersion = "explicit_mapping", request.Service, request.MappingVersion
				}
				container = &Container{
					ID: opaqueIdentity(hostID + "\x00" + rawID), HostID: hostID, Service: service,
					MappingStatus: mappingStatus, MappingVersion: mappingVersion,
					CPU: emptyMeasurement(), Memory: emptyMeasurement(), OOMEvents: emptyMeasurement(), StartEvidence: emptyMeasurement(),
					PeerContainerIDs: []string{},
				}
				containers[key] = container
			}
			metricType.set(container, makeMeasurement(series.Samples, metricResult.SourceReference, metricResult.Partial, request))
			updateLatest(&container.LastObservedAt, series.Samples)
			container.Stale = container.Stale || measurementStale(series.Samples, request)
			container.ClockSkew = container.ClockSkew || hasFutureSample(series.Samples, request.End)
		}
	}
	startResults := results["prometheus.runtime.container.start_time.v1"]
	for _, series := range startResults.Series {
		id := series.Labels["id"]
		hostID := series.Labels["host_id"]
		if id == "" || hostID != request.HostID {
			continue
		}
		container := containers[id+"\x00"+hostID]
		if container == nil || len(series.Samples) == 0 {
			continue
		}
		container.StartEvidence = makeMeasurement(series.Samples, startResults.SourceReference, startResults.Partial, request)
		if hasFutureSample(series.Samples, request.End) {
			container.ClockSkew = true
			continue
		}
		value := series.Samples[0].Value
		ambiguous := false
		for _, sample := range series.Samples {
			if sample.Value != value || math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) {
				ambiguous = true
			}
		}
		if ambiguous {
			result.Gaps = append(result.Gaps, "container_incarnation_ambiguous")
			result.Partial = true
			continue
		}
		if value > 0 && value < float64(math.MaxInt64)/float64(time.Second) {
			startedAt := time.Unix(0, int64(value*float64(time.Second))).UTC()
			if !startedAt.After(request.End) {
				container.StartTime = &startedAt
				container.InstanceID = opaqueIdentity(container.ID + "\x00" + startedAt.Format(time.RFC3339Nano))
			}
		}
	}
	ordered := make([]Container, 0, len(containers))
	for _, container := range containers {
		if container.CPU.Empty {
			result.Gaps = append(result.Gaps, "container_cpu_metrics_missing")
			result.Partial = true
		}
		if container.Memory.Empty {
			result.Gaps = append(result.Gaps, "container_memory_metrics_missing")
			result.Partial = true
		}
		if container.OOMEvents.Empty {
			result.Gaps = append(result.Gaps, "container_oom_events_missing")
			result.Partial = true
		}
		if container.StartTime == nil {
			result.Gaps = append(result.Gaps, "container_start_time_missing_or_ambiguous")
			result.Partial = true
		}
		container.Stale = container.CPU.Stale || container.Memory.Stale
		switch {
		case container.ClockSkew:
			container.State = "unknown"
		case container.CPU.Empty && container.Memory.Empty:
			container.State = "unknown"
		case container.Stale:
			container.State = "stale"
		default:
			container.State = "observed"
		}
		if measurementIncomplete(container.CPU) || measurementIncomplete(container.Memory) || measurementIncomplete(container.OOMEvents) || measurementIncomplete(container.StartEvidence) || container.ClockSkew {
			result.Partial = true
			result.Gaps = append(result.Gaps, "resource_samples_stale_or_skewed")
		}
		ordered = append(ordered, *container)
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].ID < ordered[right].ID })
	return ordered
}

func normalizeEvents(result loki.Result, request Request) []Event {
	events := make([]Event, 0, min(len(result.Entries), request.MaxLogLines))
	for _, entry := range result.Entries {
		hostID, legacyHost := entry.Labels["host_id"], entry.Labels["host"]
		if hostID != "" && legacyHost != "" && hostID != legacyHost {
			continue
		}
		if hostID == "" {
			hostID = legacyHost
		}
		if hostID != request.HostID || entry.Labels["service"] != request.Service || entry.Labels["env"] != request.Environment {
			continue
		}
		if len(events) >= request.MaxLogLines {
			break
		}
		events = append(events, Event{
			Timestamp:      entry.Timestamp.UTC(),
			Classification: "unverified_log_match", SourceReference: result.SourceReference,
			OutsideTimeWindow: entry.OutsideTimeWindow || entry.Timestamp.Before(request.Start) || entry.Timestamp.After(request.End), Line: entry.Line,
		})
	}
	return events
}

func measurementIncomplete(value Measurement) bool {
	return value.Empty || value.Stale || value.Partial
}

func compactGaps(gaps []string) []string {
	result := gaps[:0]
	for _, gap := range gaps {
		if len(result) == 0 || result[len(result)-1] != gap {
			result = append(result, gap)
		}
	}
	return result
}

// Duplicate label sets cannot be resolved by response order. Preserve identity,
// discard conflicting samples, and report the missing evidence.
func rejectDuplicateSeries(series []prometheus.Series, result *Result) []prometheus.Series {
	counts := make(map[string]int)
	keyOf := func(s prometheus.Series) string {
		return s.Labels["host_id"] + "\x00" + s.Labels["id"] + "\x00" + s.Labels["instance"]
	}
	for _, item := range series {
		counts[keyOf(item)]++
	}
	seen := make(map[string]bool)
	filtered := make([]prometheus.Series, 0, len(series))
	for _, item := range series {
		key := keyOf(item)
		if seen[key] {
			continue
		}
		seen[key] = true
		if counts[key] > 1 {
			item.Samples = nil
			result.Partial = true
			result.Gaps = append(result.Gaps, "runtime_duplicate_series")
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func makeMeasurement(samples []prometheus.Sample, source string, partial bool, request Request) Measurement {
	copyOfSamples := append([]prometheus.Sample(nil), samples...)
	return Measurement{
		Samples: copyOfSamples, SourceReference: source, Empty: len(copyOfSamples) == 0,
		Delay: measurementDelay(copyOfSamples, request.End), Stale: measurementStale(copyOfSamples, request), Partial: partial,
	}
}

func emptyMeasurement() Measurement {
	return Measurement{Samples: []prometheus.Sample{}, Empty: true, Stale: true}
}

func measurementStale(samples []prometheus.Sample, request Request) bool {
	if len(samples) == 0 {
		return true
	}
	latest := samples[0].Timestamp
	for _, sample := range samples[1:] {
		if sample.Timestamp.After(latest) {
			latest = sample.Timestamp
		}
	}
	tolerance := max(3*request.Step, time.Minute)
	return latest.Before(request.End.Add(-tolerance))
}

func updateLatest(target **time.Time, samples []prometheus.Sample) {
	for _, sample := range samples {
		if *target == nil || sample.Timestamp.After(**target) {
			timestamp := sample.Timestamp.UTC()
			*target = &timestamp
		}
	}
}

func hasFutureSample(samples []prometheus.Sample, end time.Time) bool {
	for _, sample := range samples {
		if sample.Timestamp.After(end.Add(time.Minute)) {
			return true
		}
	}
	return false
}

func measurementDelay(samples []prometheus.Sample, end time.Time) time.Duration {
	var latest time.Time
	for _, sample := range samples {
		if sample.Timestamp.After(latest) {
			latest = sample.Timestamp
		}
	}
	if latest.IsZero() || latest.After(end) {
		return 0
	}
	return end.Sub(latest)
}

func opaqueIdentity(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:8])
}
