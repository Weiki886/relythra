package diagnosis

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	lokiconnector "github.com/Weiki886/relythra/internal/connector/loki"
	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/security/redact"
)

const (
	ruleTestInvestigationID = "11111111-1111-4111-8111-111111111111"
	ruleTestServiceID       = "22222222-2222-4222-8222-222222222222"
	latencyEvidenceID       = "33333333-3333-4333-8333-333333333333"
	slowQueryEvidenceID     = "44444444-4444-4444-8444-444444444444"
)

func TestAnalyzeSlowQueryLatencyCorrelation(t *testing.T) {
	start := time.Date(2026, 11, 17, 2, 0, 0, 0, time.UTC)
	input := AnalysisInput{
		InvestigationID: ruleTestInvestigationID,
		Evidence: []Evidence{
			ruleLatencyEvidence(t, latencyEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "COMPLETE", start, start.Add(5*time.Minute), start.Add(2*time.Minute)),
			ruleSlowQueryEvidence(t, slowQueryEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "COMPLETE", start, start.Add(5*time.Minute), start.Add(3*time.Minute)),
		},
	}

	result, err := Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if result.RuleSetVersion != RuleSetVersion || result.Status != StatusCandidatesFound || len(result.Candidates) != 1 {
		t.Fatalf("analysis result = %+v", result)
	}
	candidate := result.Candidates[0]
	if candidate.RuleID != RuleSlowQueryLatency || candidate.Confidence != ConfidenceMedium ||
		candidate.EntityID != ruleTestServiceID || candidate.FaultType != "DATABASE_PERFORMANCE" {
		t.Fatalf("candidate = %+v", candidate)
	}
	if len(candidate.SupportEvidenceIDs) != 2 || candidate.SupportEvidenceIDs[0] != latencyEvidenceID || candidate.SupportEvidenceIDs[1] != slowQueryEvidenceID {
		t.Fatalf("support Evidence IDs = %v", candidate.SupportEvidenceIDs)
	}
	if len(candidate.ContradictEvidenceIDs) != 0 || candidate.TriggerChange != "" {
		t.Fatalf("rule asserted unsupported contradiction or deployment cause: %+v", candidate)
	}
}

func TestAnalyzeSlowQueryRequiresSameServiceAndInWindowObservations(t *testing.T) {
	start := time.Date(2026, 11, 17, 2, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		mutate  func([]Evidence) []Evidence
		missing []string
	}{
		{
			name: "different services",
			mutate: func(items []Evidence) []Evidence {
				items[1].EntityID = stringPointer("55555555-5555-4555-8555-555555555555")
				return items
			},
			missing: []string{"same_service"},
		},
		{
			name: "no timestamp correlation",
			mutate: func(items []Evidence) []Evidence {
				items[1] = ruleSlowQueryEvidence(t, slowQueryEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "COMPLETE", start.Add(6*time.Minute), start.Add(10*time.Minute), start.Add(7*time.Minute))
				return items
			},
			missing: []string{"overlapping_observation"},
		},
		{
			name: "log entry outside overlap",
			mutate: func(items []Evidence) []Evidence {
				items[1] = ruleSlowQueryEvidence(t, slowQueryEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "COMPLETE", start, start.Add(5*time.Minute), start.Add(6*time.Minute))
				return items
			},
			missing: []string{"slow_query_log_in_window"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			items := []Evidence{
				ruleLatencyEvidence(t, latencyEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "COMPLETE", start, start.Add(5*time.Minute), start.Add(2*time.Minute)),
				ruleSlowQueryEvidence(t, slowQueryEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "COMPLETE", start, start.Add(5*time.Minute), start.Add(3*time.Minute)),
			}
			result, err := Analyze(context.Background(), AnalysisInput{
				InvestigationID: ruleTestInvestigationID,
				Evidence:        test.mutate(items),
			})
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if result.Status != StatusInconclusive || len(result.Candidates) != 0 {
				t.Fatalf("analysis result = %+v, want inconclusive", result)
			}
			for _, requirement := range test.missing {
				if !contains(result.MissingRequirements, requirement) {
					t.Errorf("missing requirements %v do not include %q", result.MissingRequirements, requirement)
				}
			}
		})
	}
}

func TestAnalyzeSlowQueryReportsPartialEvidenceWithLowerConfidence(t *testing.T) {
	start := time.Date(2026, 11, 17, 2, 0, 0, 0, time.UTC)
	result, err := Analyze(context.Background(), AnalysisInput{
		InvestigationID: ruleTestInvestigationID,
		Evidence: []Evidence{
			ruleLatencyEvidence(t, latencyEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "PARTIAL", start, start.Add(5*time.Minute), start.Add(2*time.Minute)),
			ruleSlowQueryEvidence(t, slowQueryEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "COMPLETE", start, start.Add(5*time.Minute), start.Add(3*time.Minute)),
		},
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.Candidates) != 1 || result.Candidates[0].Confidence != ConfidenceLow || len(result.Candidates[0].MissingRequirements) == 0 {
		t.Fatalf("partial analysis result = %+v", result)
	}
}

func TestAnalyzeSlowQueryCompletePairIsNotDowngradedByAdditionalPartialEvidence(t *testing.T) {
	start := time.Date(2026, 11, 17, 2, 0, 0, 0, time.UTC)
	partialID := "55555555-5555-4555-8555-555555555555"
	result, err := Analyze(context.Background(), AnalysisInput{
		InvestigationID: ruleTestInvestigationID,
		Evidence: []Evidence{
			ruleLatencyEvidence(t, latencyEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "COMPLETE", start, start.Add(5*time.Minute), start.Add(2*time.Minute)),
			ruleSlowQueryEvidence(t, slowQueryEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "COMPLETE", start, start.Add(5*time.Minute), start.Add(3*time.Minute)),
			ruleLatencyEvidence(t, partialID, ruleTestInvestigationID, ruleTestServiceID, "PARTIAL", start, start.Add(5*time.Minute), start.Add(2*time.Minute)),
		},
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.Candidates) != 1 || result.Candidates[0].Confidence != ConfidenceMedium {
		t.Fatalf("complete pair was downgraded: %+v", result)
	}
}

func TestAnalyzeSlowQueryReturnsInconclusiveWhenEvidenceIsMissing(t *testing.T) {
	start := time.Date(2026, 11, 17, 2, 0, 0, 0, time.UTC)
	result, err := Analyze(context.Background(), AnalysisInput{
		InvestigationID: ruleTestInvestigationID,
		Evidence: []Evidence{
			ruleLatencyEvidence(t, latencyEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "COMPLETE", start, start.Add(5*time.Minute), start.Add(2*time.Minute)),
		},
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if result.Status != StatusInconclusive || len(result.Candidates) != 0 || !contains(result.MissingRequirements, "slow_query_log") {
		t.Fatalf("missing evidence result = %+v", result)
	}
}

func TestAnalyzeRejectsEvidenceFromAnotherInvestigation(t *testing.T) {
	start := time.Date(2026, 11, 17, 2, 0, 0, 0, time.UTC)
	_, err := Analyze(context.Background(), AnalysisInput{
		InvestigationID: ruleTestInvestigationID,
		Evidence: []Evidence{
			ruleLatencyEvidence(t, latencyEvidenceID, "66666666-6666-4666-8666-666666666666", ruleTestServiceID, "COMPLETE", start, start.Add(5*time.Minute), start.Add(2*time.Minute)),
		},
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-Investigation evidence error = %v, want ErrInvalidInput", err)
	}
}

func ruleLatencyEvidence(t *testing.T, id, investigationID, serviceID, completeness string, start, end, sampleAt time.Time) Evidence {
	t.Helper()
	queryParameters, err := json.Marshal(map[string]any{"template_id": "prometheus.database.query_latency.v1", "template_version": 1})
	if err != nil {
		t.Fatal(err)
	}
	valueSummary, err := json.Marshal(map[string]any{"series": []prometheusconnector.Series{{
		Labels:  map[string]string{"service": "checkout-api"},
		Samples: []prometheusconnector.Sample{{Timestamp: sampleAt, Value: 0.25}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return Evidence{
		ID: id, InvestigationID: investigationID, SourceType: "PROMETHEUS", EntityType: "SERVICE",
		EntityID: stringPointer(serviceID), ObservedStart: start, ObservedEnd: end,
		QueryParameters: queryParameters, ValueSummary: valueSummary, Completeness: completeness,
		IndependenceGroup: "prometheus:prometheus.database.query_latency.v1:v1",
	}
}

func ruleSlowQueryEvidence(t *testing.T, id, investigationID, serviceID, completeness string, start, end, entryAt time.Time) Evidence {
	t.Helper()
	queryParameters, err := json.Marshal(map[string]any{"template_id": "loki.service.slow_queries.v1", "template_version": 1})
	if err != nil {
		t.Fatal(err)
	}
	valueSummary, err := json.Marshal(map[string]any{"entries": []lokiconnector.Entry{{
		Timestamp: entryAt,
		Line:      redact.UntrustedData{Trust: "untrusted_data", Source: "loki", Content: "slow query observed", OriginalBytes: len("slow query observed")},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return Evidence{
		ID: id, InvestigationID: investigationID, SourceType: "LOKI", EntityType: "SERVICE",
		EntityID: stringPointer(serviceID), ObservedStart: start, ObservedEnd: end,
		QueryParameters: queryParameters, ValueSummary: valueSummary, Completeness: completeness,
		IndependenceGroup: "loki:loki.service.slow_queries.v1:v1",
	}
}

func stringPointer(value string) *string {
	return &value
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
