package api

import (
	"fmt"
	"net/http"

	"github.com/Weiki886/relythra/internal/diagnosis"
	"github.com/Weiki886/relythra/internal/store"
)

const maxDiagnosisEvidence = 100

type investigationDiagnosis struct {
	InvestigationID   string `json:"investigation_id"`
	EvidenceTotal     int    `json:"evidence_total"`
	EvidenceLimit     int    `json:"evidence_limit"`
	EvidenceTruncated bool   `json:"evidence_truncated"`
	diagnosis.AnalysisResult
}

func (handler *handler) getInvestigationDiagnosis(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := requireID(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "diagnosis does not accept query parameters")
		return
	}
	timeline, err := handler.reader.GetInvestigationTimeline(r.Context(), id, store.InvestigationTimelineFilter{}, maxDiagnosisEvidence, 0)
	if err != nil {
		handler.writeStoreError(w, r, err)
		return
	}
	response := investigationDiagnosis{
		InvestigationID:   id,
		EvidenceTotal:     timeline.Total,
		EvidenceLimit:     maxDiagnosisEvidence,
		EvidenceTruncated: timeline.HasMore || timeline.Total > len(timeline.Items),
		AnalysisResult: diagnosis.AnalysisResult{
			RuleSetVersion:      diagnosis.RuleSetVersion,
			Status:              diagnosis.StatusInconclusive,
			Candidates:          []diagnosis.Candidate{},
			MissingRequirements: []string{"complete_evidence_snapshot"},
		},
	}
	// A selected prefix cannot establish the absence of counterevidence.
	if response.EvidenceTruncated {
		handler.writeData(w, r, http.StatusOK, response)
		return
	}
	items := make([]diagnosis.Evidence, 0, len(timeline.Items))
	for _, item := range timeline.Items {
		items = append(items, diagnosis.Evidence{
			ID: item.ID, InvestigationID: item.InvestigationID,
			SourceType: item.SourceType, EntityType: item.EntityType, EntityID: item.EntityID,
			ObservedStart: item.ObservedStart, ObservedEnd: item.ObservedEnd,
			QueryParameters: item.QueryParameters, ValueSummary: item.ValueSummary,
			Completeness: item.Completeness, IndependenceGroup: item.IndependenceGroup,
		})
	}
	response.AnalysisResult, err = diagnosis.Analyze(r.Context(), diagnosis.AnalysisInput{InvestigationID: id, Evidence: items})
	if err != nil {
		// Invalid stored input is a server failure, not a malformed client request.
		handler.writeStoreError(w, r, fmt.Errorf("analyze persisted investigation evidence: %w", err))
		return
	}
	handler.writeData(w, r, http.StatusOK, response)
}
