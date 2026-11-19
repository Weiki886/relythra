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
	memoryEvidenceID        = "55555555-5555-4555-8555-555555555555"
	secondMemoryEvidenceID  = "66666666-6666-4666-8666-666666666666"
	configErrorEvidenceID   = "77777777-7777-4777-8777-777777777777"
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
			name: "unapproved independence group",
			mutate: func(items []Evidence) []Evidence {
				items[0].IndependenceGroup = "shared:unknown"
				return items
			},
			missing: []string{"approved_independence_groups"},
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

func TestAnalyzeUnavailableEvidenceCannotSupportCandidates(t *testing.T) {
	start := time.Date(2026, 11, 17, 2, 0, 0, 0, time.UTC)
	for _, state := range []string{"MISSING", "EXPIRED"} {
		for _, source := range []string{"PROMETHEUS", "LOKI"} {
			t.Run(source+"/"+state, func(t *testing.T) {
				items := []Evidence{
					ruleLatencyEvidence(t, latencyEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "COMPLETE", start, start.Add(5*time.Minute), start.Add(2*time.Minute)),
					ruleSlowQueryEvidence(t, slowQueryEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "COMPLETE", start, start.Add(5*time.Minute), start.Add(3*time.Minute)),
				}
				for i := range items {
					if items[i].SourceType == source {
						items[i].Completeness = state
					}
				}
				result, err := Analyze(context.Background(), AnalysisInput{InvestigationID: ruleTestInvestigationID, Evidence: items})
				if err != nil {
					t.Fatal(err)
				}
				if result.Status != StatusInconclusive || len(result.Candidates) != 0 || len(result.MissingRequirements) == 0 {
					t.Fatalf("unavailable observations supported a candidate: %+v", result)
				}
			})
		}
	}
}

func TestAnalyzeRejectsUnknownCompleteness(t *testing.T) {
	start := time.Date(2026, 11, 17, 2, 0, 0, 0, time.UTC)
	item := ruleLatencyEvidence(t, latencyEvidenceID, ruleTestInvestigationID, ruleTestServiceID, "UNKNOWN", start, start.Add(time.Minute), start)
	_, err := Analyze(context.Background(), AnalysisInput{InvestigationID: ruleTestInvestigationID, Evidence: []Evidence{item}})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown completeness error = %v, want ErrInvalidInput", err)
	}
}

func TestAnalyzeContainerMemoryGrowthNeedsThreeIncreasingSamplesFromOneSeries(t *testing.T) {
	start := time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		series  []prometheusconnector.Series
		want    bool
		missing string
	}{
		{
			name: "one series rises across three samples",
			series: []prometheusconnector.Series{memorySeries(start,
				[]float64{100, 120, 140}, []string{"container-a"})},
			want: true,
		},
		{
			name: "two samples are insufficient",
			series: []prometheusconnector.Series{memorySeries(start,
				[]float64{100, 140}, []string{"container-a"})},
			missing: "container_memory_growth_trend",
		},
		{
			name: "flat series does not show growth",
			series: []prometheusconnector.Series{memorySeries(start,
				[]float64{100, 100, 100}, []string{"container-a"})},
			missing: "container_memory_growth_trend",
		},
		{
			name: "samples from two series cannot be combined",
			series: []prometheusconnector.Series{
				memorySeries(start, []float64{100, 120}, []string{"container-a"}),
				memorySeries(start, []float64{200, 240}, []string{"container-b"}),
			},
			missing: "container_memory_growth_trend",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item := ruleContainerMemoryEvidence(t, memoryEvidenceID, "COMPLETE", start, start.Add(3*time.Minute), test.series)
			result, err := Analyze(context.Background(), AnalysisInput{
				InvestigationID: ruleTestInvestigationID,
				Evidence:        []Evidence{item},
			})
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if !test.want {
				if result.Status != StatusInconclusive || len(result.Candidates) != 0 || !contains(result.MissingRequirements, test.missing) {
					t.Fatalf("analysis = %+v, want no candidate and missing %q", result, test.missing)
				}
				return
			}
			if result.RuleSetVersion != RuleSetVersion || result.Status != StatusCandidatesFound || len(result.Candidates) != 1 {
				t.Fatalf("analysis = %+v, want one versioned candidate", result)
			}
			candidate := result.Candidates[0]
			if candidate.RuleID != "container-memory-growth-trend.v1" || candidate.FaultType != "CONTAINER_MEMORY_GROWTH_SIGNAL" ||
				candidate.EntityID != ruleTestServiceID || candidate.Confidence != ConfidenceLow ||
				len(candidate.SupportEvidenceIDs) != 1 || candidate.SupportEvidenceIDs[0] != memoryEvidenceID ||
				len(candidate.ContradictEvidenceIDs) != 0 || candidate.TriggerChange != "" ||
				!contains(candidate.MissingRequirements, "independent_memory_corroboration") ||
				!contains(candidate.MissingRequirements, "memory_leak_causality_unproven") {
				t.Fatalf("memory trend candidate exceeded its evidence: %+v", candidate)
			}
		})
	}
}

func TestAnalyzeContainerMemoryGrowthKeepsPartialAndRejectsUnavailableEvidence(t *testing.T) {
	start := time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)
	series := []prometheusconnector.Series{memorySeries(start, []float64{100, 120, 140}, []string{"container-a"})}
	partial := ruleContainerMemoryEvidence(t, memoryEvidenceID, "PARTIAL", start, start.Add(3*time.Minute), series)
	result, err := Analyze(context.Background(), AnalysisInput{InvestigationID: ruleTestInvestigationID, Evidence: []Evidence{partial}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates) != 1 || result.Candidates[0].Confidence != ConfidenceLow ||
		!contains(result.Candidates[0].MissingRequirements, "complete_memory_source_evidence") {
		t.Fatalf("partial trend candidate = %+v", result)
	}

	for _, completeness := range []string{"MISSING", "EXPIRED"} {
		t.Run(completeness, func(t *testing.T) {
			item := ruleContainerMemoryEvidence(t, memoryEvidenceID, completeness, start, start.Add(3*time.Minute), series)
			result, err := Analyze(context.Background(), AnalysisInput{InvestigationID: ruleTestInvestigationID, Evidence: []Evidence{item}})
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != StatusInconclusive || len(result.Candidates) != 0 ||
				!contains(result.MissingRequirements, "container_memory_metric_unavailable") {
				t.Fatalf("unavailable Evidence supported candidate: %+v", result)
			}
		})
	}
}

func TestAnalyzeContainerMemoryGrowthSortsEvidenceIDsAcrossSnapshots(t *testing.T) {
	start := time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)
	first := ruleContainerMemoryEvidence(t, memoryEvidenceID, "COMPLETE", start, start.Add(3*time.Minute),
		[]prometheusconnector.Series{memorySeries(start, []float64{100, 120, 140}, []string{"container-a"})})
	second := ruleContainerMemoryEvidence(t, secondMemoryEvidenceID, "COMPLETE", start, start.Add(3*time.Minute),
		[]prometheusconnector.Series{memorySeries(start, []float64{200, 240, 280}, []string{"container-b"})})
	result, err := Analyze(context.Background(), AnalysisInput{
		InvestigationID: ruleTestInvestigationID,
		Evidence:        []Evidence{second, first},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates) != 1 || len(result.Candidates[0].SupportEvidenceIDs) != 2 ||
		result.Candidates[0].SupportEvidenceIDs[0] != memoryEvidenceID || result.Candidates[0].SupportEvidenceIDs[1] != secondMemoryEvidenceID {
		t.Fatalf("memory candidate order = %+v", result.Candidates)
	}
}

func TestAnalyzeContainerMemoryGrowthRequiresApprovedGroupAndValidSamples(t *testing.T) {
	start := time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)
	valid := ruleContainerMemoryEvidence(t, memoryEvidenceID, "COMPLETE", start, start.Add(3*time.Minute),
		[]prometheusconnector.Series{memorySeries(start, []float64{100, 120, 140}, []string{"container-a"})})
	valid.IndependenceGroup = "shared:unknown"
	result, err := Analyze(context.Background(), AnalysisInput{InvestigationID: ruleTestInvestigationID, Evidence: []Evidence{valid}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates) != 0 || !contains(result.MissingRequirements, "approved_independence_groups") {
		t.Fatalf("unapproved Evidence supported candidate: %+v", result)
	}

	invalidSeries := []struct {
		name   string
		series prometheusconnector.Series
	}{
		{
			name: "negative value",
			series: prometheusconnector.Series{
				Labels: map[string]string{"container": "container-a"},
				Samples: []prometheusconnector.Sample{
					{Timestamp: start, Value: -1},
				},
			},
		},
		{
			name: "outside observation window",
			series: prometheusconnector.Series{
				Labels: map[string]string{"container": "container-a"},
				Samples: []prometheusconnector.Sample{
					{Timestamp: start.Add(-time.Minute), Value: 1},
				},
			},
		},
	}
	for _, test := range invalidSeries {
		t.Run(test.name, func(t *testing.T) {
			item := ruleContainerMemoryEvidence(t, memoryEvidenceID, "COMPLETE", start, start.Add(3*time.Minute), []prometheusconnector.Series{test.series})
			_, err := Analyze(context.Background(), AnalysisInput{InvestigationID: ruleTestInvestigationID, Evidence: []Evidence{item}})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("invalid memory sample error = %v, want ErrInvalidInput", err)
			}
		})
	}
	malformed := ruleContainerMemoryEvidence(t, memoryEvidenceID, "COMPLETE", start, start.Add(3*time.Minute), nil)
	malformed.ValueSummary = []byte(`{"series":[{"labels":{},"samples":[{"timestamp":"invalid","value":1}]}]}`)
	if _, err := Analyze(context.Background(), AnalysisInput{InvestigationID: ruleTestInvestigationID, Evidence: []Evidence{malformed}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("malformed summary error = %v, want ErrInvalidInput", err)
	}
}

func TestAnalyzeConfigurationErrorLogSignal(t *testing.T) {
	start := time.Date(2026, 11, 19, 3, 0, 0, 0, time.UTC)
	for _, completeness := range []string{"COMPLETE", "PARTIAL"} {
		t.Run(completeness, func(t *testing.T) {
			item := ruleConfigurationErrorEvidence(t, configErrorEvidenceID, completeness, start, start.Add(5*time.Minute), true)
			result, err := Analyze(context.Background(), AnalysisInput{InvestigationID: ruleTestInvestigationID, Evidence: []Evidence{item}})
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if result.RuleSetVersion != "v0.3.0" || result.Status != StatusCandidatesFound || len(result.Candidates) != 1 {
				t.Fatalf("analysis result = %+v", result)
			}
			candidate := result.Candidates[0]
			if candidate.RuleID != "configuration-error-log-signal.v1" || candidate.FaultType != "CONFIGURATION_ERROR_LOG_SIGNAL" ||
				candidate.EntityID != ruleTestServiceID || candidate.Confidence != ConfidenceLow ||
				len(candidate.SupportEvidenceIDs) != 1 || candidate.SupportEvidenceIDs[0] != configErrorEvidenceID ||
				len(candidate.ContradictEvidenceIDs) != 0 || candidate.TriggerChange != "" ||
				!contains(candidate.MissingRequirements, "independent_configuration_corroboration") ||
				!contains(candidate.MissingRequirements, "configuration_error_causality_unproven") {
				t.Fatalf("configuration signal exceeded its evidence: %+v", candidate)
			}
			if completeness == "PARTIAL" && !contains(candidate.MissingRequirements, "complete_configuration_log_evidence") {
				t.Fatalf("partial evidence gap missing: %+v", candidate)
			}
		})
	}
}

func TestAnalyzeConfigurationErrorRequiresWindowEvidenceAndApprovedGroup(t *testing.T) {
	start := time.Date(2026, 11, 19, 3, 0, 0, 0, time.UTC)
	tests := []struct {
		name         string
		completeness string
		inWindow     bool
		group        string
		mutate       func(*Evidence)
		missing      string
	}{
		{name: "missing", completeness: "MISSING", inWindow: true, missing: "configuration_error_log_unavailable"},
		{name: "expired", completeness: "EXPIRED", inWindow: true, missing: "configuration_error_log_unavailable"},
		{name: "empty", completeness: "COMPLETE", inWindow: false, missing: "configuration_error_log_in_window"},
		{name: "outside window", completeness: "COMPLETE", inWindow: true, missing: "configuration_error_log_in_window", mutate: func(item *Evidence) {
			item.ValueSummary = []byte(`{"entries":[{"timestamp":"2026-11-19T03:06:00Z","outside_time_window":true}]}`)
		}},
		{name: "unapproved group", completeness: "COMPLETE", inWindow: true, group: "shared:unknown", missing: "approved_independence_groups"},
		{name: "unknown template version", completeness: "COMPLETE", inWindow: true, mutate: func(item *Evidence) {
			item.QueryParameters = []byte(`{"template_id":"loki.service.config_errors.v1","template_version":2}`)
		}},
		{name: "wrong entity type", completeness: "COMPLETE", inWindow: true, mutate: func(item *Evidence) { item.EntityType = "HOST" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item := ruleConfigurationErrorEvidence(t, configErrorEvidenceID, test.completeness, start, start.Add(5*time.Minute), test.inWindow)
			if test.group != "" {
				item.IndependenceGroup = test.group
			}
			if test.mutate != nil {
				test.mutate(&item)
			}
			result, err := Analyze(context.Background(), AnalysisInput{InvestigationID: ruleTestInvestigationID, Evidence: []Evidence{item}})
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if len(result.Candidates) != 0 || result.Status != StatusInconclusive || (test.missing != "" && !contains(result.MissingRequirements, test.missing)) {
				t.Fatalf("analysis = %+v, want no candidate and missing %q", result, test.missing)
			}
		})
	}
}

func TestAnalyzeConfigurationErrorSupportEvidenceIsSorted(t *testing.T) {
	start := time.Date(2026, 11, 19, 3, 0, 0, 0, time.UTC)
	first := ruleConfigurationErrorEvidence(t, secondMemoryEvidenceID, "COMPLETE", start, start.Add(5*time.Minute), true)
	second := ruleConfigurationErrorEvidence(t, configErrorEvidenceID, "COMPLETE", start, start.Add(5*time.Minute), true)
	result, err := Analyze(context.Background(), AnalysisInput{
		InvestigationID: ruleTestInvestigationID,
		Evidence:        []Evidence{first, second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates) != 1 || len(result.Candidates[0].SupportEvidenceIDs) != 2 ||
		result.Candidates[0].SupportEvidenceIDs[0] != secondMemoryEvidenceID || result.Candidates[0].SupportEvidenceIDs[1] != configErrorEvidenceID {
		t.Fatalf("configuration signal support order = %+v", result.Candidates)
	}
}

func TestAnalyzeConfigurationErrorRejectsMalformedSummaryAndForeignInvestigation(t *testing.T) {
	start := time.Date(2026, 11, 19, 3, 0, 0, 0, time.UTC)
	malformed := ruleConfigurationErrorEvidence(t, configErrorEvidenceID, "COMPLETE", start, start.Add(5*time.Minute), true)
	malformed.ValueSummary = []byte(`{"entries":[`)
	if _, err := Analyze(context.Background(), AnalysisInput{InvestigationID: ruleTestInvestigationID, Evidence: []Evidence{malformed}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("malformed summary error = %v, want ErrInvalidInput", err)
	}
	foreign := ruleConfigurationErrorEvidence(t, configErrorEvidenceID, "COMPLETE", start, start.Add(5*time.Minute), true)
	foreign.InvestigationID = "88888888-8888-4888-8888-888888888888"
	if _, err := Analyze(context.Background(), AnalysisInput{InvestigationID: ruleTestInvestigationID, Evidence: []Evidence{foreign}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("foreign Evidence error = %v, want ErrInvalidInput", err)
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

func ruleContainerMemoryEvidence(
	t *testing.T,
	id, completeness string,
	start, end time.Time,
	series []prometheusconnector.Series,
) Evidence {
	t.Helper()
	queryParameters, err := json.Marshal(map[string]any{
		"template_id":      "prometheus.container.memory.v1",
		"template_version": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	valueSummary, err := json.Marshal(map[string]any{"series": series})
	if err != nil {
		t.Fatal(err)
	}
	return Evidence{
		ID: id, InvestigationID: ruleTestInvestigationID, SourceType: "PROMETHEUS", EntityType: "SERVICE",
		EntityID: stringPointer(ruleTestServiceID), ObservedStart: start, ObservedEnd: end,
		QueryParameters: queryParameters, ValueSummary: valueSummary, Completeness: completeness,
		IndependenceGroup: "prometheus:prometheus.container.memory.v1:v1",
	}
}

func ruleConfigurationErrorEvidence(t *testing.T, id, completeness string, start, end time.Time, inWindow bool) Evidence {
	t.Helper()
	queryParameters, err := json.Marshal(map[string]any{
		"template_id":      "loki.service.config_errors.v1",
		"template_version": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	entries := []lokiconnector.Entry{}
	if inWindow {
		entries = append(entries, lokiconnector.Entry{
			Timestamp: start.Add(time.Minute),
			Line:      redact.UntrustedData{Trust: "untrusted_data", Source: "loki", Content: "private configuration error log", OriginalBytes: len("private configuration error log")},
		})
	}
	valueSummary, err := json.Marshal(map[string]any{"entries": entries})
	if err != nil {
		t.Fatal(err)
	}
	return Evidence{
		ID: id, InvestigationID: ruleTestInvestigationID, SourceType: "LOKI", EntityType: "SERVICE",
		EntityID: stringPointer(ruleTestServiceID), ObservedStart: start, ObservedEnd: end,
		QueryParameters: queryParameters, ValueSummary: valueSummary, Completeness: completeness,
		IndependenceGroup: "loki:loki.service.config_errors.v1:v1",
	}
}

func memorySeries(start time.Time, values []float64, labels []string) prometheusconnector.Series {
	label := "container-a"
	if len(labels) > 0 {
		label = labels[0]
	}
	samples := make([]prometheusconnector.Sample, len(values))
	for index, value := range values {
		samples[index] = prometheusconnector.Sample{Timestamp: start.Add(time.Duration(index) * time.Minute), Value: value}
	}
	return prometheusconnector.Series{Labels: map[string]string{"container": label}, Samples: samples}
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
