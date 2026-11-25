package evidence

import (
	"context"
	"encoding/json"
	"fmt"
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
	MappingVersion   int                    `json:"mapping_version"`
	TemplateID       string                 `json:"template_id"`
	TemplateVersion  int                    `json:"template_version"`
	UnderlyingSource string                 `json:"underlying_source"`
	TimeBasis        string                 `json:"time_basis"`
}

type runtimeMeasurementObservation struct {
	EntityType       string                       `json:"entity_type"`
	EntityID         string                       `json:"entity_id"`
	HostID           string                       `json:"host_id"`
	Instance         string                       `json:"instance,omitempty"`
	InstanceID       string                       `json:"instance_id,omitempty"`
	Service          string                       `json:"service,omitempty"`
	MappingStatus    string                       `json:"mapping_status,omitempty"`
	MappingVersion   int                          `json:"mapping_version,omitempty"`
	StartTime        *time.Time                   `json:"start_time,omitempty"`
	LastObservedAt   *time.Time                   `json:"last_observed_at,omitempty"`
	State            string                       `json:"state,omitempty"`
	Stale            *bool                        `json:"stale,omitempty"`
	ClockSkew        bool                         `json:"clock_skew"`
	PeerContainerIDs []string                     `json:"peer_container_ids,omitempty"`
	Measurement      runtimeconnector.Measurement `json:"measurement"`
}

type runtimeValueSummary struct {
	OOMWindowObservations    []runtimeconnector.OOMWindowObservation `json:"oom_window_observations,omitempty"`
	Measurements             []runtimeMeasurementObservation         `json:"measurements"`
	Events                   []runtimeconnector.Event                `json:"events"`
	Gaps                     []string                                `json:"gaps"`
	Partial                  bool                                    `json:"partial"`
	SourceReferenceAvailable bool                                    `json:"source_reference_available"`
}

// FromRuntimeResult emits one record for each of the collector's seven metric
// templates and one lifecycle log template. Failed templates become source-level
// MISSING Evidence while successful templates remain available. Reusing their
// source independence groups prevents derived observations from becoming
// independent votes. It returns no records if any query fails validation,
// redaction or size bounds.
func FromRuntimeResult(ctx context.Context, result runtimeconnector.Result, metadata RuntimeEvidenceContext, filter *redact.Filter) ([]Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if filter == nil {
		return nil, redact.ErrUnsafeOutput
	}
	if result.Runtime != datasource.RuntimeDockerCompose || strings.TrimSpace(result.HostID) == "" ||
		strings.TrimSpace(result.Service) == "" || strings.TrimSpace(result.Environment) == "" ||
		result.MappingVersion < 0 || result.Start.IsZero() || result.End.IsZero() || !result.End.After(result.Start) ||
		result.End.Sub(result.Start) > runtimeconnector.MaxQueryWindow || result.Duration < 0 {
		return nil, ErrInvalidInput
	}
	templates := []string{
		"prometheus.runtime.host.cpu.v1", "prometheus.runtime.host.memory_available.v1", "prometheus.runtime.host.load.v1",
		"prometheus.runtime.container.cpu.v1", "prometheus.runtime.container.memory.v1", "prometheus.runtime.container.oom_events.v1",
		"prometheus.runtime.container.start_time.v1", "loki.container.restarts.v1",
	}
	templateIndexes := make(map[string]int, len(templates))
	for index, template := range templates {
		templateIndexes[template] = index
	}
	failuresByTemplate := make(map[string]runtimeconnector.CollectionFailure, len(result.Failures))
	for _, failure := range result.Failures {
		index, exists := templateIndexes[failure.TemplateID]
		if !exists || failure.TemplateVersion != 1 ||
			(failure.SourceType != SourcePrometheus && failure.SourceType != SourceLoki) ||
			(index == len(templates)-1) != (failure.SourceType == SourceLoki) ||
			!validCollectionFailureCode(CollectionFailureCode(failure.ReasonCode)) {
			return nil, ErrInvalidInput
		}
		if _, duplicate := failuresByTemplate[failure.TemplateID]; duplicate {
			return nil, ErrInvalidInput
		}
		failuresByTemplate[failure.TemplateID] = failure
	}
	buckets := make([][]runtimeMeasurementObservation, len(templates))
	for i := range buckets {
		buckets[i] = []runtimeMeasurementObservation{}
	}
	explicitlyMappedContainers := make(map[string]struct{}, len(result.Containers))
	containerIDs := make(map[string]int, len(result.Containers))
	peerContainerIDs := make(map[string][]string, len(result.Containers))
	oomWindows := []runtimeconnector.OOMWindowObservation{}
	for _, host := range result.Hosts {
		if host.HostID != result.HostID || invalidRuntimeObservationTime(host.LastObservedAt, result.End, host.ClockSkew) {
			return nil, ErrInvalidInput
		}
		for i, measurement := range []runtimeconnector.Measurement{host.CPU, host.MemoryAvailable, host.Load} {
			buckets[i] = append(buckets[i], runtimeMeasurementObservation{
				EntityType: "HOST", EntityID: host.HostID, HostID: host.HostID, Instance: host.Instance,
				LastObservedAt: utcTimePointer(host.LastObservedAt), ClockSkew: host.ClockSkew, Measurement: measurement,
			})
		}
	}
	for _, container := range result.Containers {
		if container.HostID != result.HostID || strings.TrimSpace(container.ID) == "" || (container.StartTime != nil && container.StartTime.IsZero()) ||
			!validRuntimeContainerState(container.State, container.Stale, container.ClockSkew) ||
			invalidRuntimeObservationTime(container.LastObservedAt, result.End, container.ClockSkew) {
			return nil, ErrInvalidInput
		}
		containerIDs[container.ID]++
		switch container.MappingStatus {
		case "explicit_mapping":
			if result.MappingVersion < 1 || container.MappingVersion != result.MappingVersion || container.Service != result.Service {
				return nil, ErrInvalidInput
			}
			explicitlyMappedContainers[container.ID] = struct{}{}
		case "raw_cgroup_only":
			if container.MappingVersion != 0 || container.Service != "" {
				return nil, ErrInvalidInput
			}
		default:
			return nil, ErrInvalidInput
		}
		windows, err := canonicalRuntimeOOMWindows(container, result.Start, result.End)
		if err != nil {
			return nil, err
		}
		oomWindows = append(oomWindows, windows...)
		for i, measurement := range []runtimeconnector.Measurement{container.CPU, container.Memory, container.OOMEvents, container.StartEvidence} {
			stale := container.Stale
			observation := runtimeMeasurementObservation{EntityType: "CONTAINER", EntityID: container.ID, HostID: container.HostID,
				InstanceID: container.InstanceID, Service: container.Service, MappingStatus: container.MappingStatus,
				MappingVersion: container.MappingVersion, LastObservedAt: utcTimePointer(container.LastObservedAt),
				State: container.State, Stale: &stale, ClockSkew: container.ClockSkew, Measurement: measurement}
			if i == 3 && container.StartTime != nil {
				started := container.StartTime.UTC()
				observation.StartTime = &started
			}
			buckets[i+3] = append(buckets[i+3], observation)
		}
	}
	mappedIDs := make([]string, 0, len(explicitlyMappedContainers))
	for containerID := range explicitlyMappedContainers {
		mappedIDs = append(mappedIDs, containerID)
	}
	sort.Strings(mappedIDs)
	for _, container := range result.Containers {
		expected := make([]string, 0, len(mappedIDs))
		if container.MappingStatus == "explicit_mapping" {
			for _, peerID := range mappedIDs {
				if peerID != container.ID {
					expected = append(expected, peerID)
				}
			}
		}
		peers := append([]string(nil), container.PeerContainerIDs...)
		sort.Strings(peers)
		if len(peers) != len(expected) || (len(expected) > 0 && containerIDs[container.ID] != 1) {
			return nil, ErrInvalidInput
		}
		for i, peerID := range peers {
			if strings.TrimSpace(peerID) == "" || peerID == container.ID || (i > 0 && peers[i-1] == peerID) ||
				peerID != expected[i] || containerIDs[peerID] != 1 {
				return nil, ErrInvalidInput
			}
		}
		if len(peers) > 0 {
			peerContainerIDs[container.ID] = peers
		}
	}
	for i := 3; i < 7; i++ {
		for j := range buckets[i] {
			buckets[i][j].PeerContainerIDs = append([]string(nil), peerContainerIDs[buckets[i][j].EntityID]...)
		}
	}
	if err := sortRuntimeObservations(oomWindows); err != nil {
		return nil, err
	}
	gaps := append([]string{}, result.Gaps...)
	sort.Strings(gaps)
	records := make([]Record, 0, len(templates))
	for i, template := range templates {
		if failure, failed := failuresByTemplate[template]; failed {
			if runtimeMeasurementsHaveData(buckets[i]) || (i == len(templates)-1 && len(result.Events) > 0) {
				return nil, ErrInvalidInput
			}
			record, err := FromCollectionFailure(ctx, CollectionGapInput{
				InvestigationID: metadata.InvestigationID, ToolCallID: metadata.ToolCallID,
				SourceType: failure.SourceType, EntityType: "HOST", EntityID: result.HostID,
				TemplateID: failure.TemplateID, TemplateVersion: failure.TemplateVersion,
				ObservedStart: result.Start, ObservedEnd: result.End, CollectedAt: metadata.CollectedAt,
				ReasonCode: CollectionFailureCode(failure.ReasonCode),
			}, filter)
			if err != nil {
				return nil, fmt.Errorf("normalize collection gap for %s: %w", template, err)
			}
			records = append(records, record)
			continue
		}
		summary := runtimeValueSummary{Measurements: buckets[i], Events: []runtimeconnector.Event{}, Gaps: gaps, Partial: result.Partial}
		if template == "prometheus.runtime.container.oom_events.v1" {
			summary.OOMWindowObservations = oomWindows
		}
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
					event.Classification != "unverified_log_match" || strings.TrimSpace(event.SourceReference) == "" ||
					!mergeRuntimeReference(&reference, event.SourceReference) {
					return nil, ErrInvalidInput
				}
				if event.ContainerID == "" {
					if event.MappingVersion != 0 {
						return nil, ErrInvalidInput
					}
				} else if event.MappingVersion != result.MappingVersion || result.MappingVersion < 1 {
					return nil, ErrInvalidInput
				} else if _, mapped := explicitlyMappedContainers[event.ContainerID]; !mapped {
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
			HostID: result.HostID, MappingVersion: result.MappingVersion, TemplateID: template, TemplateVersion: 1, UnderlyingSource: origin, TimeBasis: basis})
		if err != nil {
			return nil, ErrInvalidInput
		}
		values, err := json.Marshal(summary)
		if err != nil {
			return nil, ErrInvalidInput
		}
		sourceTimezone, sourceTimeText := sourceTimeMetadata(result.Start, result.End)
		record, err := Normalize(ctx, Input{
			InvestigationID: metadata.InvestigationID, ToolCallID: metadata.ToolCallID, CollectedAt: metadata.CollectedAt,
			SourceType: SourceRuntime, EntityType: "HOST", EntityID: result.HostID,
			ObservedStart: result.Start, ObservedEnd: result.End, RawReference: reference,
			QueryParameters: parameters, ValueSummary: values, Completeness: completeness,
			IndependenceGroup: prefix + template + ":v1", SourceTimezone: sourceTimezone,
			SourceTimeText: sourceTimeText,
		}, filter)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func runtimeMeasurementsHaveData(measurements []runtimeMeasurementObservation) bool {
	for _, observation := range measurements {
		if len(observation.Measurement.Samples) > 0 || observation.Measurement.SourceReference != "" {
			return true
		}
	}
	return false
}

func validRuntimeContainerState(state string, stale, clockSkew bool) bool {
	switch state {
	case "observed":
		return !stale && !clockSkew
	case "stale":
		return stale && !clockSkew
	case "unknown":
		return true
	default:
		return false
	}
}

func invalidRuntimeObservationTime(observedAt *time.Time, end time.Time, clockSkew bool) bool {
	return observedAt != nil && (observedAt.IsZero() || (observedAt.After(end) && !clockSkew))
}

func utcTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	utc := value.UTC()
	return &utc
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
