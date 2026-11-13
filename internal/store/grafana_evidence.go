package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

// GrafanaAlertEvidenceContext identifies the owner and collection of an alert snapshot.
type GrafanaAlertEvidenceContext struct {
	InvestigationID string
	ToolCallID      string
	CollectedAt     time.Time
}

// GrafanaAlertEvidence converts current alert facts into an immutable observation.
// Callers persisting this record must validate ownership; prefer PersistGrafanaAlertEvidence.
// Transitions share an independence group and do not establish a root cause.
func GrafanaAlertEvidence(ctx context.Context, alert Alert, meta GrafanaAlertEvidenceContext, filter *redact.Filter) (evidence.Record, error) {
	if filter == nil {
		return evidence.Record{}, redact.ErrUnsafeOutput
	}
	if !domain.IsID(alert.ID) || !domain.IsID(alert.ProjectID) ||
		(alert.ServiceID != nil && !domain.IsID(*alert.ServiceID)) ||
		(alert.Environment != nil && strings.TrimSpace(*alert.Environment) == "") ||
		(alert.Status != "FIRING" && alert.Status != "RESOLVED") ||
		strings.TrimSpace(alert.Fingerprint) == "" || strings.TrimSpace(alert.FingerprintVersion) == "" || alert.EventVersion < 1 ||
		(alert.Status == "FIRING" && alert.EndsAt != nil) {
		return evidence.Record{}, evidence.ErrInvalidInput
	}
	end := alert.StartsAt
	if alert.EndsAt != nil {
		end = *alert.EndsAt
	}
	entityType, entityID, mapping := "ALERT", alert.ID, "NEEDS_MAPPING"
	if alert.ServiceID != nil && alert.Environment != nil {
		entityType, entityID, mapping = "SERVICE", *alert.ServiceID, "MATCHED"
	}
	completeness := evidence.CompletenessComplete
	if mapping != "MATCHED" || strings.TrimSpace(alert.SourceReference) == "" || (alert.Status == "RESOLVED" && alert.EndsAt == nil) || end.After(meta.CollectedAt) {
		completeness = evidence.CompletenessPartial
	}
	summary, err := json.Marshal(struct {
		AlertID            string  `json:"alert_id"`
		ProjectID          string  `json:"project_id"`
		ServiceID          *string `json:"service_id"`
		Environment        *string `json:"environment"`
		Fingerprint        string  `json:"fingerprint"`
		FingerprintVersion string  `json:"fingerprint_version"`
		EventVersion       int64   `json:"event_version"`
		Status             string  `json:"status"`
		Severity           string  `json:"severity"`
		Summary            string  `json:"summary"`
		MappingStatus      string  `json:"mapping_status"`
		EndKnown           bool    `json:"end_known"`
	}{alert.ID, alert.ProjectID, alert.ServiceID, alert.Environment, alert.Fingerprint, alert.FingerprintVersion, alert.EventVersion, alert.Status, alert.Severity, alert.Summary, mapping, alert.EndsAt != nil})
	if err != nil {
		return evidence.Record{}, evidence.ErrInvalidInput
	}
	params, err := json.Marshal(struct {
		AlertID string `json:"alert_id"`
	}{alert.ID})
	if err != nil {
		return evidence.Record{}, evidence.ErrInvalidInput
	}
	return evidence.Normalize(ctx, evidence.Input{InvestigationID: meta.InvestigationID, ToolCallID: meta.ToolCallID, SourceType: evidence.SourceGrafana, EntityType: entityType, EntityID: entityID, ObservedStart: alert.StartsAt, ObservedEnd: end, CollectedAt: meta.CollectedAt, RawReference: alert.SourceReference, QueryParameters: params, ValueSummary: summary, Completeness: completeness, IndependenceGroup: "grafana:alert:" + alert.ID, SourceTimezone: alert.SourceTimezone, SourceTimeText: alert.SourceTimeText}, filter)
}

// PersistGrafanaAlertEvidence snapshots the canonical alert associated with the
// investigation's incident. It rejects stale mappings and unrelated alerts.
func (repository *Postgres) PersistGrafanaAlertEvidence(ctx context.Context, alertID string, meta GrafanaAlertEvidenceContext, filter *redact.Filter) (Evidence, bool, error) {
	if filter == nil {
		return Evidence{}, false, redact.ErrUnsafeOutput
	}
	if !domain.IsID(alertID) || !domain.IsID(meta.InvestigationID) || (meta.ToolCallID != "" && !domain.IsID(meta.ToolCallID)) || meta.CollectedAt.IsZero() {
		return Evidence{}, false, ErrInvalidInput
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Evidence{}, false, fmt.Errorf("begin Grafana evidence: %w", err)
	}
	defer tx.Rollback()
	item, created, err := persistGrafanaAlertEvidence(ctx, tx, alertID, meta, filter)
	if err != nil {
		return Evidence{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Evidence{}, false, fmt.Errorf("commit Grafana evidence: %w", err)
	}
	return item, created, nil
}

// persistGrafanaAlertEvidence shares ownership validation with ingestion and remapping.
// The caller owns the transaction so alert changes and evidence commit together.
func persistGrafanaAlertEvidence(ctx context.Context, tx *sql.Tx, alertID string, meta GrafanaAlertEvidenceContext, filter *redact.Filter) (Evidence, bool, error) {
	// Use the ingestion lock order: alert first, then its incident/investigation.
	// Shared locks keep the facts and their ownership stable until persistence commits.
	alert, err := scanAlert(tx.QueryRowContext(ctx, `SELECT `+alertColumns+` FROM alerts WHERE id=$1 FOR SHARE`, alertID))
	if errors.Is(err, sql.ErrNoRows) {
		return Evidence{}, false, ErrNotFound
	}
	if err != nil {
		return Evidence{}, false, fmt.Errorf("read Grafana evidence alert: %w", err)
	}
	var matches bool
	err = tx.QueryRowContext(ctx, `
 SELECT inc.alert_id IS NOT DISTINCT FROM $2::uuid
 AND inc.project_id=$3::uuid
 AND inc.service_id IS NOT DISTINCT FROM $4::uuid
 AND i.service_id IS NOT DISTINCT FROM $4::uuid
 AND inc.environment IS NOT DISTINCT FROM $5::text
 AND i.environment IS NOT DISTINCT FROM $5::text
 FROM investigations i JOIN incidents inc ON inc.id=i.incident_id
 WHERE i.id=$1 FOR SHARE OF i,inc`, meta.InvestigationID, alert.ID, alert.ProjectID, alert.ServiceID, alert.Environment).Scan(&matches)
	if errors.Is(err, sql.ErrNoRows) {
		return Evidence{}, false, ErrNotFound
	}
	if err != nil {
		return Evidence{}, false, fmt.Errorf("validate Grafana evidence ownership: %w", err)
	}
	if !matches {
		return Evidence{}, false, fmt.Errorf("%w: alert does not match investigation ownership", ErrInvalidInput)
	}
	record, err := GrafanaAlertEvidence(ctx, alert, meta, filter)
	if err != nil {
		return Evidence{}, false, fmt.Errorf("normalize Grafana evidence: %w", err)
	}
	item, created, err := persistValidatedEvidence(ctx, tx, record)
	if err != nil {
		return Evidence{}, false, err
	}
	return item, created, nil
}
