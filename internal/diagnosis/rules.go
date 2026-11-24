package diagnosis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	lokiconnector "github.com/Weiki886/relythra/internal/connector/loki"
	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	runtimeconnector "github.com/Weiki886/relythra/internal/connector/runtime"
	"github.com/Weiki886/relythra/internal/domain"
)

const (
	RuleSetVersion               = "v0.5.0"
	RuleSlowQueryLatency         = "slow-query-latency-correlation.v1"
	RuleContainerMemoryGrowth    = "container-memory-growth-trend.v1"
	RuleConfigurationErrorSignal = "configuration-error-log-signal.v1"
	RuleHostResourcePressure     = "host-resource-pressure-signal.v1"
	RuleContainerRestartSignal   = "container-restart-signal.v1"

	StatusCandidatesFound = "CANDIDATES_FOUND"
	StatusInconclusive    = "INCONCLUSIVE"

	ConfidenceLow    = "LOW"
	ConfidenceMedium = "MEDIUM"

	latencyTemplateID            = "prometheus.database.query_latency.v1"
	containerMemoryTemplateID    = "prometheus.container.memory.v1"
	slowQueryTemplateID          = "loki.service.slow_queries.v1"
	configurationErrorTemplateID = "loki.service.config_errors.v1"
	hostCPUtemplateID            = "prometheus.runtime.host.cpu.v1"
	hostMemoryTemplateID         = "prometheus.runtime.host.memory_available.v1"
	hostLoadTemplateID           = "prometheus.runtime.host.load.v1"
	containerStartTimeTemplateID = "prometheus.runtime.container.start_time.v1"
	containerRestartTemplateID   = "loki.container.restarts.v1"
	containerRestartCorrelation  = 5 * time.Minute
)

var ErrInvalidInput = errors.New("invalid diagnosis input")

// Evidence is the read-only subset of persisted Evidence consumed by rules.
type Evidence struct {
	ID                string          `json:"id"`
	InvestigationID   string          `json:"investigation_id"`
	SourceType        string          `json:"source_type"`
	EntityType        string          `json:"entity_type"`
	EntityID          *string         `json:"entity_id"`
	ObservedStart     time.Time       `json:"observed_start"`
	ObservedEnd       time.Time       `json:"observed_end"`
	QueryParameters   json.RawMessage `json:"query_parameters"`
	ValueSummary      json.RawMessage `json:"value_summary"`
	Completeness      string          `json:"completeness"`
	IndependenceGroup string          `json:"independence_group"`
}

type AnalysisInput struct {
	InvestigationID string
	Evidence        []Evidence
}

type AnalysisResult struct {
	RuleSetVersion      string      `json:"rule_set_version"`
	Status              string      `json:"status"`
	Candidates          []Candidate `json:"candidates"`
	MissingRequirements []string    `json:"missing_requirements"`
}

type Candidate struct {
	EntityType            string   `json:"entity_type"`
	RuleID                string   `json:"rule_id"`
	FaultType             string   `json:"fault_type"`
	EntityID              string   `json:"entity_id"`
	Confidence            string   `json:"confidence"`
	SupportEvidenceIDs    []string `json:"support_evidence_ids"`
	ContradictEvidenceIDs []string `json:"contradict_evidence_ids"`
	MissingRequirements   []string `json:"missing_requirements"`
	TriggerChange         string   `json:"trigger_change,omitempty"`
}

type queryMetadata struct {
	TemplateID       string `json:"template_id"`
	TemplateVersion  int    `json:"template_version"`
	Runtime          string `json:"runtime"`
	Service          string `json:"service"`
	Environment      string `json:"environment"`
	HostID           string `json:"host_id"`
	MappingVersion   int    `json:"mapping_version"`
	UnderlyingSource string `json:"underlying_source"`
}

type prometheusSummary struct {
	Series []prometheusconnector.Series `json:"series"`
}

type lokiSummary struct {
	Entries []lokiconnector.Entry `json:"entries"`
}

type runtimeMeasurementObservation struct {
	EntityType     string                       `json:"entity_type"`
	EntityID       string                       `json:"entity_id"`
	HostID         string                       `json:"host_id"`
	Service        string                       `json:"service"`
	MappingStatus  string                       `json:"mapping_status"`
	MappingVersion int                          `json:"mapping_version"`
	StartTime      *time.Time                   `json:"start_time"`
	LastObservedAt *time.Time                   `json:"last_observed_at"`
	State          string                       `json:"state"`
	Stale          *bool                        `json:"stale"`
	ClockSkew      bool                         `json:"clock_skew"`
	Measurement    runtimeconnector.Measurement `json:"measurement"`
}

type runtimeSummary struct {
	Measurements          []runtimeMeasurementObservation         `json:"measurements"`
	Events                []runtimeconnector.Event                `json:"events"`
	OOMWindowObservations []runtimeconnector.OOMWindowObservation `json:"oom_window_observations"`
	Gaps                  []string                                `json:"gaps"`
	Partial               bool                                    `json:"partial"`
}

type matchedEvidence struct {
	evidence Evidence
	complete bool
}

type containerRestartScope struct {
	hostID         string
	service        string
	environment    string
	mappingVersion int
	containerID    string
}

type containerStartChange struct {
	scope         containerRestartScope
	at            time.Time
	observedStart time.Time
	observedEnd   time.Time
	evidenceID    string
	complete      bool
}

type containerRestartEvent struct {
	scope         containerRestartScope
	at            time.Time
	observedStart time.Time
	observedEnd   time.Time
	evidenceID    string
}

type containerRestartIdentity struct {
	hostID      string
	containerID string
}

// Analyze evaluates the bounded v0 slow-query rule without making external calls
// or attributing the observed symptoms to a deployment.
func Analyze(ctx context.Context, input AnalysisInput) (AnalysisResult, error) {
	result := AnalysisResult{
		RuleSetVersion: RuleSetVersion,
		Status:         StatusInconclusive,
		Candidates:     []Candidate{},
	}
	if ctx == nil || !domain.IsID(input.InvestigationID) {
		return AnalysisResult{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return AnalysisResult{}, err
	}

	seenIDs := make(map[string]struct{}, len(input.Evidence))
	var latencyEvidence, memoryEvidence, slowQueryEvidence, configurationErrorEvidence []matchedEvidence
	latencySourcePresent, memorySourcePresent, memoryUsableSourcePresent, slowQuerySourcePresent, configurationErrorSourcePresent, configurationErrorUsableSourcePresent := false, false, false, false, false, false
	hostSourcePresent := map[string]bool{}
	hostUsableSourcePresent := map[string]bool{}
	hostTrendPresent := map[string]bool{}
	hostTrendByHost := make(map[string]map[string]matchedEvidence)
	hostIndependenceMismatch := make(map[string]bool)
	containerStartChanges := make([]containerStartChange, 0)
	containerRestartEvents := make([]containerRestartEvent, 0)
	independenceMismatch := false
	for _, item := range input.Evidence {
		if !domain.IsID(item.ID) || item.InvestigationID != input.InvestigationID {
			return AnalysisResult{}, ErrInvalidInput
		}
		if _, duplicate := seenIDs[item.ID]; duplicate {
			return AnalysisResult{}, ErrInvalidInput
		}
		seenIDs[item.ID] = struct{}{}
		if item.ObservedStart.IsZero() || item.ObservedEnd.IsZero() || item.ObservedEnd.Before(item.ObservedStart) {
			return AnalysisResult{}, ErrInvalidInput
		}
		switch item.Completeness {
		case "COMPLETE", "PARTIAL", "MISSING", "EXPIRED":
		default:
			return AnalysisResult{}, ErrInvalidInput
		}
		if item.SourceType == "RUNTIME" && item.EntityType == "HOST" {
			metadata, recognized, err := registeredTemplate(item)
			if err != nil {
				return AnalysisResult{}, err
			}
			if !recognized || metadata.TemplateVersion != 1 {
				continue
			}
			if item.EntityID == nil || !validHostID(*item.EntityID) {
				return AnalysisResult{}, ErrInvalidInput
			}
			switch metadata.TemplateID {
			case containerStartTimeTemplateID:
				if item.Completeness == "MISSING" || item.Completeness == "EXPIRED" {
					continue
				}
				if item.IndependenceGroup != "prometheus:"+containerStartTimeTemplateID+":v1" {
					independenceMismatch = true
					continue
				}
				changes, err := findContainerStartChanges(item, metadata, *item.EntityID)
				if err != nil {
					return AnalysisResult{}, err
				}
				containerStartChanges = append(containerStartChanges, changes...)
				continue
			case containerRestartTemplateID:
				if item.Completeness == "MISSING" || item.Completeness == "EXPIRED" {
					continue
				}
				if item.IndependenceGroup != "loki:"+containerRestartTemplateID+":v1" {
					independenceMismatch = true
					continue
				}
				events, err := findContainerRestartEvents(item, metadata, *item.EntityID)
				if err != nil {
					return AnalysisResult{}, err
				}
				containerRestartEvents = append(containerRestartEvents, events...)
				continue
			default:
				templateID := metadata.TemplateID
				hostSourcePresent[templateID] = true
				if item.Completeness == "MISSING" || item.Completeness == "EXPIRED" {
					continue
				}
				hostUsableSourcePresent[templateID] = true
				if item.IndependenceGroup != "prometheus:"+templateID+":v1" {
					hostIndependenceMismatch[*item.EntityID] = true
					independenceMismatch = true
					continue
				}
				trend, err := hasHostResourceTrend(item.ValueSummary, *item.EntityID, item.ObservedStart, item.ObservedEnd, item.ObservedStart, item.ObservedEnd, templateID)
				if err != nil {
					return AnalysisResult{}, err
				}
				if trend {
					hostTrendPresent[templateID] = true
					if hostTrendByHost[*item.EntityID] == nil {
						hostTrendByHost[*item.EntityID] = make(map[string]matchedEvidence)
					}
					hostTrendByHost[*item.EntityID][templateID] = matchedEvidence{evidence: item, complete: item.Completeness == "COMPLETE"}
				}
				continue
			}
		}
		if item.EntityType != "SERVICE" || item.EntityID == nil || !domain.IsID(*item.EntityID) {
			continue
		}

		metadata, recognized, err := registeredTemplate(item)
		if err != nil {
			return AnalysisResult{}, err
		}
		if !recognized {
			continue
		}
		if metadata.TemplateVersion != 1 {
			continue
		}
		entry := matchedEvidence{evidence: item, complete: item.Completeness == "COMPLETE"}
		switch {
		case item.SourceType == "PROMETHEUS" && metadata.TemplateID == latencyTemplateID:
			latencySourcePresent = true
			if item.Completeness == "MISSING" || item.Completeness == "EXPIRED" {
				continue
			}
			if item.IndependenceGroup != "prometheus:prometheus.database.query_latency.v1:v1" {
				independenceMismatch = true
				continue
			}
			var summary prometheusSummary
			if err := json.Unmarshal(item.ValueSummary, &summary); err != nil {
				return AnalysisResult{}, fmt.Errorf("%w: decode Prometheus Evidence summary", ErrInvalidInput)
			}
			if hasLatencySample(summary, item.ObservedStart, item.ObservedEnd) {
				latencyEvidence = append(latencyEvidence, entry)
			}
		case item.SourceType == "PROMETHEUS" && metadata.TemplateID == containerMemoryTemplateID:
			memorySourcePresent = true
			if item.Completeness == "MISSING" || item.Completeness == "EXPIRED" {
				continue
			}
			memoryUsableSourcePresent = true
			if item.IndependenceGroup != "prometheus:prometheus.container.memory.v1:v1" {
				independenceMismatch = true
				continue
			}
			var summary prometheusSummary
			if err := json.Unmarshal(item.ValueSummary, &summary); err != nil {
				return AnalysisResult{}, fmt.Errorf("%w: decode container memory Evidence summary", ErrInvalidInput)
			}
			increasing, err := hasIncreasingMemoryTrend(summary, item.ObservedStart, item.ObservedEnd)
			if err != nil {
				return AnalysisResult{}, err
			}
			if increasing {
				memoryEvidence = append(memoryEvidence, entry)
			}
		case item.SourceType == "LOKI" && metadata.TemplateID == slowQueryTemplateID:
			slowQuerySourcePresent = true
			if item.Completeness == "MISSING" || item.Completeness == "EXPIRED" {
				continue
			}
			if item.IndependenceGroup != "loki:loki.service.slow_queries.v1:v1" {
				independenceMismatch = true
				continue
			}
			var summary lokiSummary
			if err := json.Unmarshal(item.ValueSummary, &summary); err != nil {
				return AnalysisResult{}, fmt.Errorf("%w: decode Loki Evidence summary", ErrInvalidInput)
			}
			if hasLogEntryInWindow(summary, item.ObservedStart, item.ObservedEnd) {
				slowQueryEvidence = append(slowQueryEvidence, entry)
			}
		case item.SourceType == "LOKI" && metadata.TemplateID == configurationErrorTemplateID:
			configurationErrorSourcePresent = true
			if item.Completeness == "MISSING" || item.Completeness == "EXPIRED" {
				continue
			}
			configurationErrorUsableSourcePresent = true
			if item.IndependenceGroup != "loki:loki.service.config_errors.v1:v1" {
				independenceMismatch = true
				continue
			}
			var summary lokiSummary
			if err := json.Unmarshal(item.ValueSummary, &summary); err != nil {
				return AnalysisResult{}, fmt.Errorf("%w: decode configuration error Evidence summary", ErrInvalidInput)
			}
			if hasLogEntryInWindow(summary, item.ObservedStart, item.ObservedEnd) {
				configurationErrorEvidence = append(configurationErrorEvidence, entry)
			}
		}
	}

	missing := make(map[string]struct{})
	if !latencySourcePresent {
		missing["database_latency_metric"] = struct{}{}
	}
	if !slowQuerySourcePresent {
		missing["slow_query_log"] = struct{}{}
	}
	if !configurationErrorSourcePresent {
		missing["configuration_error_log"] = struct{}{}
	}
	if configurationErrorSourcePresent && !configurationErrorUsableSourcePresent {
		missing["configuration_error_log_unavailable"] = struct{}{}
	}
	if !memorySourcePresent {
		missing["container_memory_metric"] = struct{}{}
	}
	if memorySourcePresent && !memoryUsableSourcePresent {
		missing["container_memory_metric_unavailable"] = struct{}{}
	}
	if latencySourcePresent && len(latencyEvidence) == 0 {
		missing["database_latency_sample_in_window"] = struct{}{}
	}
	if slowQuerySourcePresent && len(slowQueryEvidence) == 0 {
		missing["slow_query_log_in_window"] = struct{}{}
	}
	if configurationErrorUsableSourcePresent && len(configurationErrorEvidence) == 0 {
		missing["configuration_error_log_in_window"] = struct{}{}
	}
	if memoryUsableSourcePresent && len(memoryEvidence) == 0 {
		missing["container_memory_growth_trend"] = struct{}{}
	}
	if independenceMismatch {
		missing["approved_independence_groups"] = struct{}{}
	}
	for _, templateID := range []string{hostCPUtemplateID, hostMemoryTemplateID, hostLoadTemplateID} {
		if !hostSourcePresent[templateID] {
			missing[hostMetricRequirement(templateID)] = struct{}{}
		} else if !hostUsableSourcePresent[templateID] {
			missing[hostMetricRequirement(templateID)+"_unavailable"] = struct{}{}
		} else if !hostTrendPresent[templateID] {
			missing[hostMetricRequirement(templateID)+"_trend"] = struct{}{}
		}
	}

	byService := make(map[string]*Candidate)
	completePairByService := make(map[string]bool)
	for _, latency := range latencyEvidence {
		for _, slowQuery := range slowQueryEvidence {
			serviceID := *latency.evidence.EntityID
			if serviceID != *slowQuery.evidence.EntityID {
				missing["same_service"] = struct{}{}
				continue
			}
			windowStart := maxTime(latency.evidence.ObservedStart, slowQuery.evidence.ObservedStart)
			windowEnd := minTime(latency.evidence.ObservedEnd, slowQuery.evidence.ObservedEnd)
			if windowEnd.Before(windowStart) {
				missing["overlapping_observation"] = struct{}{}
				continue
			}
			if !hasLatencySampleInWindow(latency.evidence.ValueSummary, windowStart, windowEnd) ||
				!hasSlowQueryInWindow(slowQuery.evidence.ValueSummary, windowStart, windowEnd) {
				missing["slow_query_log_in_window"] = struct{}{}
				continue
			}

			candidate := byService[serviceID]
			if candidate == nil {
				candidate = &Candidate{
					EntityType: "SERVICE", RuleID: RuleSlowQueryLatency, FaultType: "DATABASE_PERFORMANCE", EntityID: serviceID,
					Confidence: ConfidenceMedium, SupportEvidenceIDs: []string{},
					ContradictEvidenceIDs: []string{}, MissingRequirements: []string{},
				}
				byService[serviceID] = candidate
			}
			candidate.SupportEvidenceIDs = appendUnique(candidate.SupportEvidenceIDs, latency.evidence.ID, slowQuery.evidence.ID)
			if latency.complete && slowQuery.complete {
				completePairByService[serviceID] = true
			}
		}
	}

	serviceIDs := make([]string, 0, len(byService))
	for id := range byService {
		serviceIDs = append(serviceIDs, id)
	}
	sort.Strings(serviceIDs)
	for _, id := range serviceIDs {
		candidate := byService[id]
		if !completePairByService[id] {
			candidate.Confidence = ConfidenceLow
			candidate.MissingRequirements = append(candidate.MissingRequirements, "complete_source_evidence")
		}
		sort.Strings(candidate.SupportEvidenceIDs)
		sort.Strings(candidate.MissingRequirements)
		result.Candidates = append(result.Candidates, *candidate)
	}

	memoryByService := make(map[string]*Candidate)
	completeMemoryByService := make(map[string]bool)
	for _, memory := range memoryEvidence {
		serviceID := *memory.evidence.EntityID
		candidate := memoryByService[serviceID]
		if candidate == nil {
			candidate = &Candidate{
				EntityType: "SERVICE", RuleID: RuleContainerMemoryGrowth, FaultType: "CONTAINER_MEMORY_GROWTH_SIGNAL",
				EntityID: serviceID, Confidence: ConfidenceLow,
				SupportEvidenceIDs: []string{}, ContradictEvidenceIDs: []string{},
				MissingRequirements: []string{"independent_memory_corroboration", "memory_leak_causality_unproven"},
			}
			memoryByService[serviceID] = candidate
		}
		candidate.SupportEvidenceIDs = appendUnique(candidate.SupportEvidenceIDs, memory.evidence.ID)
		if memory.complete {
			completeMemoryByService[serviceID] = true
		}
	}
	memoryServiceIDs := make([]string, 0, len(memoryByService))
	for id := range memoryByService {
		memoryServiceIDs = append(memoryServiceIDs, id)
	}
	sort.Strings(memoryServiceIDs)
	for _, id := range memoryServiceIDs {
		candidate := memoryByService[id]
		if !completeMemoryByService[id] {
			candidate.MissingRequirements = append(candidate.MissingRequirements, "complete_memory_source_evidence")
		}
		sort.Strings(candidate.SupportEvidenceIDs)
		sort.Strings(candidate.MissingRequirements)
		result.Candidates = append(result.Candidates, *candidate)
	}

	hostIDs := make([]string, 0, len(hostTrendByHost))
	for hostID := range hostTrendByHost {
		hostIDs = append(hostIDs, hostID)
	}
	sort.Strings(hostIDs)
	for _, hostID := range hostIDs {
		trends := hostTrendByHost[hostID]
		if hostIndependenceMismatch[hostID] || len(trends) != 3 {
			continue
		}
		items := []matchedEvidence{trends[hostCPUtemplateID], trends[hostMemoryTemplateID], trends[hostLoadTemplateID]}
		windowStart := items[0].evidence.ObservedStart
		windowEnd := items[0].evidence.ObservedEnd
		for _, item := range items[1:] {
			windowStart = maxTime(windowStart, item.evidence.ObservedStart)
			windowEnd = minTime(windowEnd, item.evidence.ObservedEnd)
		}
		if windowEnd.Before(windowStart) {
			missing["host_resource_observation_overlap"] = struct{}{}
			continue
		}
		validOverlap := true
		for index, templateID := range []string{hostCPUtemplateID, hostMemoryTemplateID, hostLoadTemplateID} {
			trend, err := hasHostResourceTrend(items[index].evidence.ValueSummary, hostID, items[index].evidence.ObservedStart, items[index].evidence.ObservedEnd, windowStart, windowEnd, templateID)
			if err != nil {
				return AnalysisResult{}, err
			}
			if !trend {
				validOverlap = false
				missing[hostMetricRequirement(templateID)+"_trend_in_overlap"] = struct{}{}
			}
		}
		if !validOverlap {
			continue
		}
		candidate := &Candidate{
			EntityType: "HOST", RuleID: RuleHostResourcePressure, FaultType: "HOST_RESOURCE_PRESSURE_SIGNAL", EntityID: hostID, Confidence: ConfidenceLow,
			SupportEvidenceIDs: []string{}, ContradictEvidenceIDs: []string{},
			MissingRequirements: []string{"independent_resource_corroboration", "host_pressure_causality_unproven"},
		}
		for _, item := range items {
			candidate.SupportEvidenceIDs = append(candidate.SupportEvidenceIDs, item.evidence.ID)
			if !item.complete {
				candidate.MissingRequirements = append(candidate.MissingRequirements, "complete_host_resource_evidence")
			}
		}
		sort.Strings(candidate.SupportEvidenceIDs)
		sort.Strings(candidate.MissingRequirements)
		result.Candidates = append(result.Candidates, *candidate)
	}

	configurationByService := make(map[string]*Candidate)
	completeConfigurationByService := make(map[string]bool)
	for _, configurationError := range configurationErrorEvidence {
		serviceID := *configurationError.evidence.EntityID
		candidate := configurationByService[serviceID]
		if candidate == nil {
			candidate = &Candidate{
				EntityType: "SERVICE", RuleID: RuleConfigurationErrorSignal, FaultType: "CONFIGURATION_ERROR_LOG_SIGNAL",
				EntityID: serviceID, Confidence: ConfidenceLow,
				SupportEvidenceIDs: []string{}, ContradictEvidenceIDs: []string{},
				MissingRequirements: []string{"independent_configuration_corroboration", "configuration_error_causality_unproven"},
			}
			configurationByService[serviceID] = candidate
		}
		candidate.SupportEvidenceIDs = appendUnique(candidate.SupportEvidenceIDs, configurationError.evidence.ID)
		if configurationError.complete {
			completeConfigurationByService[serviceID] = true
		}
	}
	configurationServiceIDs := make([]string, 0, len(configurationByService))
	for id := range configurationByService {
		configurationServiceIDs = append(configurationServiceIDs, id)
	}
	sort.Strings(configurationServiceIDs)
	for _, id := range configurationServiceIDs {
		candidate := configurationByService[id]
		if !completeConfigurationByService[id] {
			candidate.MissingRequirements = append(candidate.MissingRequirements, "complete_configuration_log_evidence")
		}
		sort.Strings(candidate.SupportEvidenceIDs)
		sort.Strings(candidate.MissingRequirements)
		result.Candidates = append(result.Candidates, *candidate)
	}
	restartCandidates := make(map[containerRestartIdentity]*Candidate)
	for _, change := range containerStartChanges {
		for _, event := range containerRestartEvents {
			windowStart := maxTime(change.observedStart, event.observedStart)
			windowEnd := minTime(change.observedEnd, event.observedEnd)
			if event.scope != change.scope || windowEnd.Before(windowStart) ||
				change.at.Before(windowStart) || change.at.After(windowEnd) || event.at.Before(windowStart) || event.at.After(windowEnd) ||
				event.at.Before(change.at.Add(-containerRestartCorrelation)) || event.at.After(change.at.Add(containerRestartCorrelation)) {
				continue
			}
			identity := containerRestartIdentity{hostID: change.scope.hostID, containerID: change.scope.containerID}
			candidate := restartCandidates[identity]
			if candidate == nil {
				candidate = &Candidate{
					EntityType: "CONTAINER", RuleID: RuleContainerRestartSignal, FaultType: "CONTAINER_RESTART_SIGNAL",
					EntityID: change.scope.containerID, Confidence: ConfidenceLow,
					SupportEvidenceIDs: []string{}, ContradictEvidenceIDs: []string{},
					MissingRequirements: []string{"independent_restart_corroboration", "lifecycle_log_unverified", "restart_causality_unproven"},
				}
				restartCandidates[identity] = candidate
			}
			candidate.SupportEvidenceIDs = appendUnique(candidate.SupportEvidenceIDs, change.evidenceID, event.evidenceID)
			if !change.complete {
				candidate.MissingRequirements = appendUnique(candidate.MissingRequirements, "complete_start_time_evidence")
			}
		}
	}
	for _, candidate := range restartCandidates {
		sort.Strings(candidate.SupportEvidenceIDs)
		sort.Strings(candidate.MissingRequirements)
		result.Candidates = append(result.Candidates, *candidate)
	}

	sort.Slice(result.Candidates, func(left, right int) bool {
		if result.Candidates[left].RuleID == result.Candidates[right].RuleID {
			return result.Candidates[left].EntityID < result.Candidates[right].EntityID
		}
		return result.Candidates[left].RuleID < result.Candidates[right].RuleID
	})
	result.MissingRequirements = sortedKeys(missing)
	if len(result.Candidates) > 0 {
		result.Status = StatusCandidatesFound
	}
	return result, nil
}

func registeredTemplate(item Evidence) (queryMetadata, bool, error) {
	if item.SourceType != "PROMETHEUS" && item.SourceType != "LOKI" && item.SourceType != "RUNTIME" {
		return queryMetadata{}, false, nil
	}
	var metadata queryMetadata
	if err := json.Unmarshal(item.QueryParameters, &metadata); err != nil {
		return queryMetadata{}, false, fmt.Errorf("%w: decode Evidence query parameters", ErrInvalidInput)
	}
	if metadata.TemplateID == "" || metadata.TemplateVersion <= 0 {
		return queryMetadata{}, false, fmt.Errorf("%w: missing Evidence template identity", ErrInvalidInput)
	}
	if item.SourceType == "PROMETHEUS" &&
		(metadata.TemplateID == latencyTemplateID || metadata.TemplateID == containerMemoryTemplateID) ||
		item.SourceType == "LOKI" && (metadata.TemplateID == slowQueryTemplateID || metadata.TemplateID == configurationErrorTemplateID) ||
		item.SourceType == "RUNTIME" && (metadata.TemplateID == hostCPUtemplateID || metadata.TemplateID == hostMemoryTemplateID || metadata.TemplateID == hostLoadTemplateID || metadata.TemplateID == containerStartTimeTemplateID || metadata.TemplateID == containerRestartTemplateID) {
		return metadata, true, nil
	}
	return metadata, false, nil
}

func validHostID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		valid := character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '.' || character == ':' || character == '-'
		if !valid || (index == 0 && !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9')) {
			return false
		}
	}
	return true
}

func hostMetricRequirement(templateID string) string {
	switch templateID {
	case hostCPUtemplateID:
		return "host_cpu_metric"
	case hostMemoryTemplateID:
		return "host_memory_available_metric"
	default:
		return "host_load_metric"
	}
}

func validContainerEvidenceID(value string) bool {
	if len(value) != 16 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func findContainerStartChanges(item Evidence, metadata queryMetadata, hostID string) ([]containerStartChange, error) {
	if metadata.Runtime != "docker-compose" || metadata.HostID != hostID || metadata.MappingVersion < 1 || metadata.UnderlyingSource != "PROMETHEUS" {
		return nil, nil
	}
	var summary runtimeSummary
	if err := json.Unmarshal(item.ValueSummary, &summary); err != nil {
		return nil, fmt.Errorf("%w: decode container start-time Evidence", ErrInvalidInput)
	}
	changes := make([]containerStartChange, 0)
	for _, observation := range summary.Measurements {
		if observation.EntityType != "CONTAINER" || observation.HostID != hostID ||
			observation.MappingStatus != "explicit_mapping" || observation.MappingVersion != metadata.MappingVersion ||
			observation.Service != metadata.Service || !validContainerEvidenceID(observation.EntityID) ||
			observation.Stale == nil || *observation.Stale || observation.ClockSkew || observation.State != "observed" {
			continue
		}
		measurement := observation.Measurement
		if measurement.Stale || measurement.Partial || measurement.Empty || len(measurement.Samples) < 2 {
			continue
		}
		samples := append([]prometheusconnector.Sample(nil), measurement.Samples...)
		valid := true
		for _, sample := range samples {
			if sample.Timestamp.IsZero() || sample.Timestamp.Before(item.ObservedStart) || sample.Timestamp.After(item.ObservedEnd) ||
				math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) || sample.Value <= 0 || sample.Value >= float64(math.MaxInt64) {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		sort.SliceStable(samples, func(left, right int) bool { return samples[left].Timestamp.Before(samples[right].Timestamp) })
		for index := 1; index < len(samples); index++ {
			previous, current := samples[index-1], samples[index]
			if !current.Timestamp.After(previous.Timestamp) {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		for index := 1; index < len(samples); index++ {
			previous, current := samples[index-1], samples[index]
			if current.Value < previous.Value {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		for index := 1; index < len(samples); index++ {
			previous, current := samples[index-1], samples[index]
			if current.Value == previous.Value {
				continue
			}
			startedAt := time.Unix(int64(current.Value), 0).UTC()
			if !startedAt.After(previous.Timestamp) || startedAt.After(current.Timestamp) {
				continue
			}
			changes = append(changes, containerStartChange{
				scope: containerRestartScope{hostID: hostID, service: metadata.Service, environment: metadata.Environment,
					mappingVersion: metadata.MappingVersion, containerID: observation.EntityID},
				at: startedAt, observedStart: item.ObservedStart, observedEnd: item.ObservedEnd,
				evidenceID: item.ID, complete: item.Completeness == "COMPLETE",
			})
		}
	}
	return changes, nil
}

func findContainerRestartEvents(item Evidence, metadata queryMetadata, hostID string) ([]containerRestartEvent, error) {
	if metadata.Runtime != "docker-compose" || metadata.HostID != hostID || metadata.MappingVersion < 1 || metadata.UnderlyingSource != "LOKI" {
		return nil, nil
	}
	var summary runtimeSummary
	if err := json.Unmarshal(item.ValueSummary, &summary); err != nil {
		return nil, fmt.Errorf("%w: decode container lifecycle Evidence", ErrInvalidInput)
	}
	events := make([]containerRestartEvent, 0)
	for _, event := range summary.Events {
		if event.Timestamp.IsZero() || event.Timestamp.Before(item.ObservedStart) || event.Timestamp.After(item.ObservedEnd) ||
			event.OutsideTimeWindow || event.ContainerID == "" || event.MappingVersion != metadata.MappingVersion ||
			event.Classification != "unverified_log_match" || event.Line.Trust != "untrusted_data" || event.Line.Source != "loki" ||
			!strings.Contains(strings.ToLower(event.Line.Content), "restart") || event.SourceReference == "" {
			continue
		}
		events = append(events, containerRestartEvent{
			scope: containerRestartScope{hostID: hostID, service: metadata.Service, environment: metadata.Environment,
				mappingVersion: metadata.MappingVersion, containerID: event.ContainerID},
			at: event.Timestamp.UTC(), observedStart: item.ObservedStart, observedEnd: item.ObservedEnd, evidenceID: item.ID,
		})
	}
	return events, nil
}

func hasHostResourceTrend(raw json.RawMessage, hostID string, evidenceStart, evidenceEnd, windowStart, windowEnd time.Time, templateID string) (bool, error) {
	var summary runtimeSummary
	if err := json.Unmarshal(raw, &summary); err != nil {
		return false, fmt.Errorf("%w: decode host runtime Evidence summary", ErrInvalidInput)
	}
	for _, observation := range summary.Measurements {
		if observation.EntityType != "HOST" || observation.EntityID != hostID || observation.HostID != hostID {
			continue
		}
		samples := make([]prometheusconnector.Sample, 0, len(observation.Measurement.Samples))
		for _, sample := range observation.Measurement.Samples {
			if sample.Timestamp.IsZero() || sample.Timestamp.Before(evidenceStart) || sample.Timestamp.After(evidenceEnd) || math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) || sample.Value < 0 {
				return false, fmt.Errorf("%w: invalid host resource sample", ErrInvalidInput)
			}
			if sample.Timestamp.Before(windowStart) || sample.Timestamp.After(windowEnd) {
				continue
			}
			samples = append(samples, sample)
		}
		sort.SliceStable(samples, func(left, right int) bool {
			return samples[left].Timestamp.Before(samples[right].Timestamp)
		})
		for index := 2; index < len(samples); index++ {
			first, second, third := samples[index-2], samples[index-1], samples[index]
			if !first.Timestamp.Before(second.Timestamp) || !second.Timestamp.Before(third.Timestamp) {
				continue
			}
			if hostResourceTrend(templateID, first.Value, second.Value, third.Value) {
				return true, nil
			}
		}
	}
	return false, nil
}

func hostResourceTrend(templateID string, first, second, third float64) bool {
	switch templateID {
	case hostCPUtemplateID, hostLoadTemplateID:
		return first < second && second < third
	case hostMemoryTemplateID:
		return first > second && second > third
	default:
		return false
	}
}

func hasIncreasingMemoryTrend(summary prometheusSummary, start, end time.Time) (bool, error) {
	for _, series := range summary.Series {
		samples := append([]prometheusconnector.Sample(nil), series.Samples...)
		for _, sample := range samples {
			if sample.Timestamp.IsZero() || sample.Timestamp.Before(start) || sample.Timestamp.After(end) ||
				math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) || sample.Value < 0 {
				return false, fmt.Errorf("%w: invalid container memory sample", ErrInvalidInput)
			}
		}
		sort.SliceStable(samples, func(left, right int) bool {
			return samples[left].Timestamp.Before(samples[right].Timestamp)
		})
		for index := 2; index < len(samples); index++ {
			first, second, third := samples[index-2], samples[index-1], samples[index]
			if first.Timestamp.Before(second.Timestamp) && second.Timestamp.Before(third.Timestamp) &&
				first.Value < second.Value && second.Value < third.Value {
				return true, nil
			}
		}
	}
	return false, nil
}

func hasLatencySample(summary prometheusSummary, start, end time.Time) bool {
	for _, series := range summary.Series {
		for _, sample := range series.Samples {
			if inWindow(sample.Timestamp, start, end) {
				return true
			}
		}
	}
	return false
}

func hasLogEntryInWindow(summary lokiSummary, start, end time.Time) bool {
	for _, entry := range summary.Entries {
		if !entry.OutsideTimeWindow && inWindow(entry.Timestamp, start, end) {
			return true
		}
	}
	return false
}

func hasLatencySampleInWindow(raw json.RawMessage, start, end time.Time) bool {
	var summary prometheusSummary
	return json.Unmarshal(raw, &summary) == nil && hasLatencySample(summary, start, end)
}

func hasSlowQueryInWindow(raw json.RawMessage, start, end time.Time) bool {
	var summary lokiSummary
	return json.Unmarshal(raw, &summary) == nil && hasLogEntryInWindow(summary, start, end)
}

func inWindow(value, start, end time.Time) bool {
	return !value.IsZero() && !value.Before(start) && !value.After(end)
}

func maxTime(left, right time.Time) time.Time {
	if left.After(right) {
		return left
	}
	return right
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range additions {
		if _, exists := seen[value]; exists {
			continue
		}
		values = append(values, value)
		seen[value] = struct{}{}
	}
	return values
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}
