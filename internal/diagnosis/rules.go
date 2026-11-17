package diagnosis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	lokiconnector "github.com/Weiki886/relythra/internal/connector/loki"
	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/domain"
)

const (
	RuleSetVersion       = "v0.1.0"
	RuleSlowQueryLatency = "slow-query-latency-correlation.v1"

	StatusCandidatesFound = "CANDIDATES_FOUND"
	StatusInconclusive    = "INCONCLUSIVE"

	ConfidenceLow    = "LOW"
	ConfidenceMedium = "MEDIUM"

	latencyTemplateID   = "prometheus.database.query_latency.v1"
	slowQueryTemplateID = "loki.service.slow_queries.v1"
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
	TemplateID      string `json:"template_id"`
	TemplateVersion int    `json:"template_version"`
}

type prometheusSummary struct {
	Series []prometheusconnector.Series `json:"series"`
}

type lokiSummary struct {
	Entries []lokiconnector.Entry `json:"entries"`
}

type matchedEvidence struct {
	evidence Evidence
	complete bool
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
	var latencyEvidence, slowQueryEvidence []matchedEvidence
	latencySourcePresent, slowQuerySourcePresent := false, false
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
		case item.SourceType == "LOKI" && metadata.TemplateID == slowQueryTemplateID:
			slowQuerySourcePresent = true
			if item.IndependenceGroup != "loki:loki.service.slow_queries.v1:v1" {
				independenceMismatch = true
				continue
			}
			var summary lokiSummary
			if err := json.Unmarshal(item.ValueSummary, &summary); err != nil {
				return AnalysisResult{}, fmt.Errorf("%w: decode Loki Evidence summary", ErrInvalidInput)
			}
			if hasSlowQueryEntry(summary, item.ObservedStart, item.ObservedEnd) {
				slowQueryEvidence = append(slowQueryEvidence, entry)
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
	if latencySourcePresent && len(latencyEvidence) == 0 {
		missing["database_latency_sample_in_window"] = struct{}{}
	}
	if slowQuerySourcePresent && len(slowQueryEvidence) == 0 {
		missing["slow_query_log_in_window"] = struct{}{}
	}
	if independenceMismatch {
		missing["approved_independence_groups"] = struct{}{}
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
					RuleID: RuleSlowQueryLatency, FaultType: "DATABASE_PERFORMANCE", EntityID: serviceID,
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
	result.MissingRequirements = sortedKeys(missing)
	if len(result.Candidates) > 0 {
		result.Status = StatusCandidatesFound
	}
	return result, nil
}

func registeredTemplate(item Evidence) (queryMetadata, bool, error) {
	if item.SourceType != "PROMETHEUS" && item.SourceType != "LOKI" {
		return queryMetadata{}, false, nil
	}
	var metadata queryMetadata
	if err := json.Unmarshal(item.QueryParameters, &metadata); err != nil {
		return queryMetadata{}, false, fmt.Errorf("%w: decode Evidence query parameters", ErrInvalidInput)
	}
	if metadata.TemplateID == "" || metadata.TemplateVersion <= 0 {
		return queryMetadata{}, false, fmt.Errorf("%w: missing Evidence template identity", ErrInvalidInput)
	}
	if item.SourceType == "PROMETHEUS" && metadata.TemplateID == latencyTemplateID ||
		item.SourceType == "LOKI" && metadata.TemplateID == slowQueryTemplateID {
		return metadata, true, nil
	}
	return metadata, false, nil
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

func hasSlowQueryEntry(summary lokiSummary, start, end time.Time) bool {
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
	return json.Unmarshal(raw, &summary) == nil && hasSlowQueryEntry(summary, start, end)
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
