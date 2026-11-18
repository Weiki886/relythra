package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/diagnosis"
	"github.com/Weiki886/relythra/internal/store"
)

const diagnosisPath = "/api/v1/investigations/" + reportID + "/diagnosis"

func TestDiagnosisReturnsTraceableCandidatesFromOneUnfilteredSnapshot(t *testing.T) {
	reader := &fakeReader{timeline: diagnosisTimeline()}
	response := serve(NewHandler(reader, discardLogger()), http.MethodGet, diagnosisPath)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data struct {
			InvestigationID   string `json:"investigation_id"`
			EvidenceTotal     int    `json:"evidence_total"`
			EvidenceLimit     int    `json:"evidence_limit"`
			EvidenceTruncated bool   `json:"evidence_truncated"`
			diagnosis.AnalysisResult
		} `json:"data"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	data := envelope.Data
	if data.InvestigationID != reportID || data.EvidenceTotal != 2 || data.EvidenceLimit != 100 || data.EvidenceTruncated ||
		data.RuleSetVersion != diagnosis.RuleSetVersion || data.Status != diagnosis.StatusCandidatesFound || len(data.Candidates) != 1 {
		t.Fatalf("diagnosis = %+v", data)
	}
	candidate := data.Candidates[0]
	if candidate.Confidence != diagnosis.ConfidenceMedium || candidate.TriggerChange != "" ||
		!reflect.DeepEqual(candidate.SupportEvidenceIDs, []string{evidenceID, deploymentID}) {
		t.Fatalf("candidate = %+v", candidate)
	}
	if envelope.RequestID == "" || envelope.RequestID != response.Header().Get("X-Request-ID") {
		t.Fatalf("request ID = %q, header = %q", envelope.RequestID, response.Header().Get("X-Request-ID"))
	}
	if reader.calls != 1 || reader.timelineID != reportID || reader.limit != 100 || reader.offset != 0 || reader.filter != (store.InvestigationTimelineFilter{}) {
		t.Fatalf("unexpected store read: %+v", reader)
	}
	for _, forbidden := range []string{"private-query", "private-log", "secret-ref", "raw_reference", "query_parameters", "value_summary", "relations"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Errorf("response contains %q", forbidden)
		}
	}
}

func TestDiagnosisInsufficientEvidenceAndReadBounds(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(*store.InvestigationTimeline)
		missing string
	}{
		{"empty", func(timeline *store.InvestigationTimeline) { timeline.Items = nil; timeline.Total = 0 }, "slow_query_log"},
		{"partial", func(timeline *store.InvestigationTimeline) { timeline.Items[0].Completeness = "PARTIAL" }, ""},
		{"expired", func(timeline *store.InvestigationTimeline) { timeline.Items[0].Completeness = "EXPIRED" }, "database_latency_sample_in_window"},
		{"missing", func(timeline *store.InvestigationTimeline) { timeline.Items[1].Completeness = "MISSING" }, "slow_query_log_in_window"},
		{"truncated", func(timeline *store.InvestigationTimeline) { timeline.Total = 101; timeline.HasMore = true }, "complete_evidence_snapshot"},
	} {
		t.Run(test.name, func(t *testing.T) {
			timeline := diagnosisTimeline()
			test.mutate(&timeline)
			response := serve(NewHandler(&fakeReader{timeline: timeline}, discardLogger()), http.MethodGet, diagnosisPath)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			var envelope struct {
				Data struct {
					diagnosis.AnalysisResult
					EvidenceTruncated bool `json:"evidence_truncated"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			result := envelope.Data
			if test.name == "partial" {
				if result.Status != diagnosis.StatusCandidatesFound || len(result.Candidates) != 1 || result.Candidates[0].Confidence != diagnosis.ConfidenceLow {
					t.Fatalf("partial result = %+v", result)
				}
				return
			}
			if result.Status != diagnosis.StatusInconclusive || len(result.Candidates) != 0 || result.Candidates == nil ||
				!strings.Contains(strings.Join(result.MissingRequirements, ","), test.missing) || result.EvidenceTruncated != timeline.HasMore {
				t.Fatalf("insufficient result = %+v", result)
			}
		})
	}
}

func TestDiagnosisRejectsInvalidRequestsBeforeReadingStore(t *testing.T) {
	for _, test := range []struct {
		name, method, path string
		status             int
	}{
		{"method", http.MethodPost, diagnosisPath, http.StatusMethodNotAllowed},
		{"id", http.MethodGet, "/api/v1/investigations/invalid/diagnosis", http.StatusBadRequest},
		{"filter", http.MethodGet, diagnosisPath + "?source_type=PROMETHEUS", http.StatusBadRequest},
		{"pagination", http.MethodGet, diagnosisPath + "?limit=1&offset=1", http.StatusBadRequest},
		{"unknown", http.MethodGet, diagnosisPath + "?query=arbitrary", http.StatusBadRequest},
		{"empty query", http.MethodGet, diagnosisPath + "?", http.StatusBadRequest},
		{"malformed", http.MethodGet, diagnosisPath + "?%zz", http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &fakeReader{}
			response := serve(NewHandler(reader, discardLogger()), test.method, test.path)
			if response.Code != test.status || reader.calls != 0 {
				t.Fatalf("status = %d, calls = %d, body = %s", response.Code, reader.calls, response.Body.String())
			}
			if test.status == http.StatusMethodNotAllowed && response.Header().Get("Allow") != http.MethodGet {
				t.Fatal("missing Allow header")
			}
		})
	}
}

func TestDiagnosisMapsStorageAndInvalidPersistedEvidenceErrors(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		invalid bool
		status  int
		code    string
	}{
		{"not found", store.ErrNotFound, false, http.StatusNotFound, "not_found"},
		{"storage failure", errors.New("private-query secret-ref"), false, http.StatusInternalServerError, "internal_error"},
		{"invalid persisted summary", nil, true, http.StatusInternalServerError, "internal_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &fakeReader{timeline: diagnosisTimeline(), err: test.err}
			if test.invalid {
				reader.timeline.Items[0].ValueSummary = json.RawMessage(`{"series":"private-query"}`)
			}
			response := serve(NewHandler(reader, discardLogger()), http.MethodGet, diagnosisPath)
			assertErrorResponse(t, response, test.status, test.code)
			if strings.Contains(response.Body.String(), "private-query") || strings.Contains(response.Body.String(), "secret-ref") {
				t.Fatal("internal details leaked")
			}
		})
	}
}

func diagnosisTimeline() store.InvestigationTimeline {
	start := time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)
	serviceID := "44444444-4444-4444-8444-444444444444"
	items := []store.InvestigationTimelineItem{
		{Evidence: store.Evidence{ID: evidenceID, SourceType: "PROMETHEUS", QueryParameters: json.RawMessage(`{"template_id":"prometheus.database.query_latency.v1","template_version":1}`), ValueSummary: json.RawMessage(`{"series":[{"samples":[{"timestamp":"2026-11-18T02:02:00Z","value":0.25}]}]}`), IndependenceGroup: "prometheus:prometheus.database.query_latency.v1:v1"}},
		{Evidence: store.Evidence{ID: deploymentID, SourceType: "LOKI", QueryParameters: json.RawMessage(`{"template_id":"loki.service.slow_queries.v1","template_version":1}`), ValueSummary: json.RawMessage(`{"entries":[{"timestamp":"2026-11-18T02:03:00Z","line":{"trust":"untrusted_data","source":"loki","content":"private-log"}}]}`), IndependenceGroup: "loki:loki.service.slow_queries.v1:v1"}},
	}
	for i := range items {
		items[i].InvestigationID = reportID
		items[i].EntityType = "SERVICE"
		items[i].EntityID = &serviceID
		items[i].ObservedStart = start
		items[i].ObservedEnd = start.Add(5 * time.Minute)
		items[i].Completeness = "COMPLETE"
		items[i].QueryText = "private-query"
		items[i].RawReference = "secret-ref"
	}
	return store.InvestigationTimeline{InvestigationID: reportID, Items: items, Total: 2, Limit: 100}
}
