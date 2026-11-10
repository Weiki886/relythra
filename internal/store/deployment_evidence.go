package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

// DeploymentEvidenceContext identifies the investigation that owns the event.
// The caller must verify the event belongs to that investigation.
type DeploymentEvidenceContext struct {
	InvestigationID string
	ToolCallID      string
	CollectedAt     time.Time
}

// DeploymentEvidence snapshots the known facts of one deployment event.
func DeploymentEvidence(ctx context.Context, event DeploymentEvent, meta DeploymentEvidenceContext, filter *redact.Filter) (evidence.Record, error) {
	if filter == nil {
		return evidence.Record{}, redact.ErrUnsafeOutput
	}
	for _, id := range []string{event.ID, event.ProjectID, event.ServiceID, event.ReleaseID} {
		if !domain.IsID(id) {
			return evidence.Record{}, evidence.ErrInvalidInput
		}
	}
	if !domain.DeploymentStatus(event.Status).Valid() || event.EventVersion < 1 || event.InstanceCount < 0 || strings.TrimSpace(event.Environment) == "" || strings.TrimSpace(event.SourceSystem) == "" {
		return evidence.Record{}, evidence.ErrInvalidInput
	}
	var conflicts []string
	if err := json.Unmarshal(event.SourceConflicts, &conflicts); err != nil || conflicts == nil {
		return evidence.Record{}, evidence.ErrInvalidInput
	}
	switch event.SourceConsistency {
	case "MATCHED", "UNVERIFIED":
		if len(conflicts) != 0 {
			return evidence.Record{}, evidence.ErrInvalidInput
		}
	case "SOURCE_CONFLICT":
		if len(conflicts) == 0 {
			return evidence.Record{}, evidence.ErrInvalidInput
		}
	default:
		return evidence.Record{}, evidence.ErrInvalidInput
	}
	end := event.StartedAt
	if event.FinishedAt != nil {
		end = *event.FinishedAt
	}
	status := domain.DeploymentStatus(event.Status)
	partial := event.FinishedAt == nil || strings.TrimSpace(event.SourceReference) == "" || event.SourceConsistency != "MATCHED" ||
		status == domain.DeploymentUnknown || status == domain.DeploymentPending || status == domain.DeploymentInProgress || end.After(meta.CollectedAt)
	completeness := evidence.CompletenessComplete
	if partial {
		completeness = evidence.CompletenessPartial
	}
	summary, err := json.Marshal(struct {
		ProjectID         string   `json:"project_id"`
		ReleaseID         string   `json:"release_id"`
		Environment       string   `json:"environment"`
		SourceSystem      string   `json:"source_system"`
		Status            string   `json:"status"`
		Finished          bool     `json:"finished"`
		Version           string   `json:"version"`
		CommitSHA         string   `json:"commit_sha"`
		ImageDigest       string   `json:"image_digest"`
		InstanceCount     int      `json:"instance_count"`
		EventVersion      int64    `json:"event_version"`
		SourceConsistency string   `json:"source_consistency"`
		SourceConflicts   []string `json:"source_conflicts"`
	}{event.ProjectID, event.ReleaseID, event.Environment, event.SourceSystem, event.Status, event.FinishedAt != nil, event.Version, event.CommitSHA, event.ImageDigest, event.InstanceCount, event.EventVersion, event.SourceConsistency, conflicts})
	if err != nil {
		return evidence.Record{}, evidence.ErrInvalidInput
	}
	params, err := json.Marshal(struct {
		DeploymentEventID string `json:"deployment_event_id"`
	}{event.ID})
	if err != nil {
		return evidence.Record{}, evidence.ErrInvalidInput
	}
	return evidence.Normalize(ctx, evidence.Input{InvestigationID: meta.InvestigationID, ToolCallID: meta.ToolCallID, SourceType: evidence.SourceDeployment, EntityType: "SERVICE", EntityID: event.ServiceID, ObservedStart: event.StartedAt, ObservedEnd: end, CollectedAt: meta.CollectedAt, RawReference: event.SourceReference, QueryParameters: params, ValueSummary: summary, Completeness: completeness, IndependenceGroup: "deployment:" + event.ID, SourceTimezone: event.SourceTimezone, SourceTimeText: event.SourceTimeText}, filter)
}
