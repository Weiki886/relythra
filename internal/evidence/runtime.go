package evidence

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/connector/prometheus"
	runtimeconnector "github.com/Weiki886/relythra/internal/connector/runtime"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/security/redact"
)

// RuntimeEvidenceContext supplies ownership and collection time, which are not
// part of the runtime connector's observation.
type RuntimeEvidenceContext struct {
	InvestigationID string
	ToolCallID      string
	CollectedAt     time.Time
}

type runtimeQueryParameters struct {
	Runtime          datasource.RuntimeType `json:"runtime"`
	Service          string                 `json:"service"`
	Environment      string                 `json:"environment"`
	HostID           string                 `json:"host_id"`
	TemplateID       string                 `json:"template_id"`
	TemplateVersion  int                    `json:"template_version"`
	UnderlyingSource string                 `json:"underlying_source"`
	TimeBasis        string                 `json:"time_basis"`
}

type runtimeMeasurementObservation struct {
	EntityType    string                       `json:"entity_type"`
	EntityID      string                       `json:"entity_id"`
	HostID        string                       `json:"host_id"`
	Instance      string                       `json:"instance,omitempty"`
	InstanceID    string                       `json:"instance_id,omitempty"`
	Service       string                       `json:"service,omitempty"`
	MappingStatus string                       `json:"mapping_status,omitempty"`
	StartTime     *time.Time                   `json:"start_time,omitempty"`
	Measurement   runtimeconnector.Measurement `json:"measurement"`
}

type runtimeValueSummary struct {
	Measurements             []runtimeMeasurementObservation `json:"measurements"`
	Events                   []runtimeconnector.Event        `json:"events"`
	Gaps                     []string                        `json:"gaps"`
	Partial                  bool                            `json:"partial"`
	SourceReferenceAvailable bool                            `json:"source_reference_available"`
}

// FromRuntimeResult emits one record for each of the collector's seven metric
// templates and one lifecycle log template. Reusing their source independence
// groups prevents derived runtime observations from becoming independent votes.
// It returns no records if any query fails validation, redaction or size bounds.
func FromRuntimeResult(ctx context.Context, result runtimeconnector.Result, metadata RuntimeEvidenceContext, filter *redact.Filter) ([]Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if filter == nil {
		return nil, redact.ErrUnsafeOutput
	}
	if result.Runtime != datasource.RuntimeDockerCompose || strings.TrimSpace(result.HostID) == "" ||
		strings.TrimSpace(result.Service) == "" || strings.TrimSpace(result.Environment) == "" ||
		result.Start.IsZero() || result.End.IsZero() || !result.End.After(result.Start) ||
		result.End.Sub(result.Start) > runtimeconnector.MaxQueryWindow || result.Duration < 0 {
		return nil, ErrInvalidInput
	}
	templates := []string{
		"prometheus.runtime.host.cpu.v1", "prometheus.runtime.host.memory_available.v1", "prometheus.runtime.host.load.v1",
		"prometheus.runtime.container.cpu.v1", "prometheus.runtime.container.memory.v1", "prometheus.runtime.container.oom_events.v1",
		"prometheus.runtime.container.start_time.v1", "loki.container.restarts.v1",
	}
	buckets := make([][]runtimeMeasurementObservation, len(templates))
	for i := range buckets {
		buckets[i] = []runtimeMeasurementObservation{}
	}
	for _, host := range result.Hosts {
		if host.HostID != result.HostID {
			return nil, ErrInvalidInput
		}
		for i, measurement := range []runtimeconnector.Measurement{host.CPU, host.MemoryAvailable, host.Load} {
			buckets[i] = append(buckets[i], runtimeMeasurementObservation{EntityType: "HOST", EntityID: host.HostID, HostID: host.HostID, Instance: host.Instance, Measurement: measurement})
		}
	}
	for _, container := range result.Containers {
		if container.HostID != result.HostID || strings.TrimSpace(container.ID) == "" || (container.StartTime != nil && container.StartTime.IsZero()) {
			return nil, ErrInvalidInput
		}
		for i, measurement := range []runtimeconnector.Measurement{container.CPU, container.Memory, container.OOMEvents, container.StartEvidence} {
			observation := runtimeMeasurementObservation{EntityType: "CONTAINER", EntityID: container.ID, HostID: container.HostID,
				InstanceID: container.InstanceID, Service: container.Service, MappingStatus: container.MappingStatus, Measurement: measurement}
			if i == 3 && container.StartTime != nil {
				started := container.StartTime.UTC()
				observation.StartTime = &started
			}
			buckets[i+3] = append(buckets[i+3], observation)
		}
	}
	gaps := append([]string{}, result.Gaps...)
	sort.Strings(gaps)
	records := make([]Record, 0, len(templates))
	for i, template := range templates {
		summary := runtimeValueSummary{Measurements: buckets[i], Events: []runtimeconnector.Event{}, Gaps: gaps, Partial: result.Partial}
		partial := result.Partial || len(gaps) > 0
		hasData, hasEmpty := false, false
		reference := ""
		for j := range summary.Measurements {
			measurement := &summary.Measurements[j].Measurement
			if err := canonicalRuntimeMeasurement(measurement); err != nil {
				return nil, err
			}
			if !mergeRuntimeReference(&reference, measurement.SourceReference) {
				return nil, ErrInvalidInput
			}
			partial = partial || measurement.Stale || measurement.Partial
			hasEmpty = hasEmpty || measurement.Empty
			for _, sample := range measurement.Samples {
				hasData = true
				partial = partial || sample.Timestamp.Before(result.Start) || sample.Timestamp.After(result.End) || sample.Timestamp.After(metadata.CollectedAt)
			}
		}
		origin, prefix, basis := SourcePrometheus, "prometheus:", "query_evaluation_time"
		if i == len(templates)-1 {
			origin, prefix, basis = SourceLoki, "loki:", "unverified_log_time"
			for _, event := range result.Events {
				if event.Timestamp.IsZero() || event.Line.Trust != "untrusted_data" || event.Line.Source != "loki" ||
					event.Classification != "unverified_log_match" || event.ContainerID != "" || strings.TrimSpace(event.SourceReference) == "" ||
					!mergeRuntimeReference(&reference, event.SourceReference) {
					return nil, ErrInvalidInput
				}
				event.Timestamp = event.Timestamp.UTC()
				summary.Events = append(summary.Events, event)
				// A log match is always unverified, even inside the query window.
				partial, hasData = true, true
			}
		}
		if err := sortRuntimeObservations(summary.Measurements); err != nil {
			return nil, err
		}
		if err := sortRuntimeObservations(summary.Events); err != nil {
			return nil, err
		}
		completeness := CompletenessComplete
		switch {
		case partial || (hasData && hasEmpty):
			completeness = CompletenessPartial
		case !hasData:
			completeness = CompletenessMissing
		}
		summary.SourceReferenceAvailable = reference != ""
		parameters, err := json.Marshal(runtimeQueryParameters{Runtime: result.Runtime, Service: result.Service, Environment: result.Environment,
			HostID: result.HostID, TemplateID: template, TemplateVersion: 1, UnderlyingSource: origin, TimeBasis: basis})
		if err != nil {
			return nil, ErrInvalidInput
		}
		values, err := json.Marshal(summary)
		if err != nil {
			return nil, ErrInvalidInput
		}
		record, err := Normalize(ctx, Input{
			InvestigationID: metadata.InvestigationID, ToolCallID: metadata.ToolCallID, CollectedAt: metadata.CollectedAt,
			SourceType: SourceRuntime, EntityType: "HOST", EntityID: result.HostID,
			ObservedStart: result.Start, ObservedEnd: result.End, RawReference: reference,
			QueryParameters: parameters, ValueSummary: values, Completeness: completeness,
			IndependenceGroup: prefix + template + ":v1", SourceTimezone: "UTC",
			SourceTimeText: result.Start.UTC().Format(time.RFC3339Nano) + "/" + result.End.UTC().Format(time.RFC3339Nano),
		}, filter)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

// Copy before sorting: the connector result may be replayed by another consumer.
func canonicalRuntimeMeasurement(measurement *runtimeconnector.Measurement) error {
	if measurement.Delay < 0 || measurement.Empty != (len(measurement.Samples) == 0) ||
		(!measurement.Empty && strings.TrimSpace(measurement.SourceReference) == "") {
		return ErrInvalidInput
	}
	samples := make([]prometheus.Sample, len(measurement.Samples))
	for i, sample := range measurement.Samples {
		if sample.Timestamp.IsZero() || math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) {
			return ErrInvalidInput
		}
		sample.Timestamp = sample.Timestamp.UTC()
		samples[i] = sample
	}
	if err := sortRuntimeObservations(samples); err != nil {
		return err
	}
	measurement.Samples = samples
	return nil
}

func mergeRuntimeReference(common *string, reference string) bool {
	if reference == "" {
		return true
	}
	if strings.TrimSpace(reference) == "" || (*common != "" && *common != reference) {
		return false
	}
	*common = reference
	return true
}

// Use the entire projected observation as a tie breaker, preserving duplicate
// observations without depending on upstream entity/event/sample ordering.
func sortRuntimeObservations[T any](values []T) error {
	type keyed struct {
		value T
		key   string
	}
	ordered := make([]keyed, len(values))
	for i, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			return ErrInvalidInput
		}
		ordered[i] = keyed{value: value, key: string(encoded)}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].key < ordered[j].key })
	for i, value := range ordered {
		values[i] = value.value
	}
	return nil
}
