package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/security/redact"
)

type GrafanaAlertInput struct {
	ProjectSlug        string
	ServiceSlug        string
	Environment        string
	Fingerprint        string
	FingerprintVersion string
	Status             string
	Severity           string
	Summary            string
	StartsAt           time.Time
	EndsAt             *time.Time
	Labels             json.RawMessage
	Annotations        json.RawMessage
	RedactedPayload    json.RawMessage
	SourceReference    string
	SourceTimezone     string
	SourceTimeText     string
}

type GrafanaAlertResult struct {
	Alert           Alert  `json:"alert"`
	IncidentID      string `json:"incident_id"`
	InvestigationID string `json:"investigation_id,omitempty"`
	MatchState      string `json:"match_state"`
	Created         bool   `json:"created"`
	Duplicate       bool   `json:"duplicate"`
	DeploymentCount int    `json:"deployment_count"`
}

type GrafanaAlertRepository interface {
	ClaimDeploymentWebhookSignature(context.Context, []byte, time.Time) (bool, error)
	IngestGrafanaAlerts(context.Context, []GrafanaAlertInput, string, *redact.Filter) ([]GrafanaAlertResult, error)
	RemapGrafanaAlert(context.Context, string, int64, string, string, *redact.Filter) (GrafanaAlertResult, error)
}

func (repository *Postgres) RemapGrafanaAlert(
	ctx context.Context,
	alertID string,
	expectedVersion int64,
	serviceID string,
	environment string,
	filter *redact.Filter,
) (GrafanaAlertResult, error) {
	if filter == nil {
		return GrafanaAlertResult{}, redact.ErrUnsafeOutput
	}
	if !domain.IsID(alertID) || !domain.IsID(serviceID) || expectedVersion < 1 || !validGrafanaEnvironment(environment) {
		return GrafanaAlertResult{}, ErrInvalidInput
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return GrafanaAlertResult{}, fmt.Errorf("begin Grafana alert remapping: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	alert, err := scanAlert(tx.QueryRowContext(ctx, `SELECT `+alertColumns+` FROM alerts WHERE id = $1 FOR UPDATE`, alertID))
	if errors.Is(err, sql.ErrNoRows) {
		return GrafanaAlertResult{}, ErrNotFound
	}
	if err != nil {
		return GrafanaAlertResult{}, fmt.Errorf("read Grafana alert for remapping: %w", err)
	}
	if alert.EventVersion != expectedVersion {
		return GrafanaAlertResult{}, ErrConflict
	}
	var projectID string
	if err := tx.QueryRowContext(ctx, `
		SELECT project_id::text FROM services WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL
	`, serviceID, alert.ProjectID).Scan(&projectID); errors.Is(err, sql.ErrNoRows) {
		return GrafanaAlertResult{}, ErrInvalidInput
	} else if err != nil {
		return GrafanaAlertResult{}, fmt.Errorf("validate remapped service: %w", err)
	}
	updated, err := scanAlert(tx.QueryRowContext(ctx, `
		UPDATE alerts SET service_id = $2, environment = $3, event_version = event_version + 1,
			labels = jsonb_set(labels, '{mapping_status}', '"MATCHED"'::jsonb, true)
		WHERE id = $1 RETURNING `+alertColumns,
		alertID, serviceID, environment))
	if err != nil {
		return GrafanaAlertResult{}, fmt.Errorf("update Grafana alert mapping: %w", err)
	}
	var incidentID string
	if err := tx.QueryRowContext(ctx, `
		UPDATE incidents SET service_id = $2, environment = $3,
			labels = jsonb_set(labels, '{mapping_status}', '"MATCHED"'::jsonb, true)
		WHERE alert_id = $1 RETURNING id::text
	`, alertID, serviceID, environment).Scan(&incidentID); err != nil {
		return GrafanaAlertResult{}, fmt.Errorf("update remapped Grafana incident: %w", err)
	}
	result := GrafanaAlertResult{Alert: updated, IncidentID: incidentID, MatchState: "MATCHED"}
	if updated.Status == "FIRING" {
		var investigationID string
		err := tx.QueryRowContext(ctx, `SELECT id::text FROM investigations WHERE incident_id = $1 ORDER BY attempt DESC LIMIT 1`, incidentID).Scan(&investigationID)
		if errors.Is(err, sql.ErrNoRows) {
			err = tx.QueryRowContext(ctx, `
				INSERT INTO investigations (incident_id, service_id, environment)
				VALUES ($1, $2, $3) RETURNING id::text
			`, incidentID, serviceID, environment).Scan(&investigationID)
			if err == nil {
				_, err = tx.ExecContext(ctx, `
					INSERT INTO investigation_transition_audits (investigation_id, from_status, to_status, version)
					VALUES ($1, NULL, 'RECEIVED', 1)
				`, investigationID)
			}
		}
		if err != nil {
			return GrafanaAlertResult{}, fmt.Errorf("create remapped Grafana investigation: %w", err)
		}
		result.InvestigationID = investigationID
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO deployment_candidates (project_id, incident_id, deployment_event_id, match_status, match_reason)
			SELECT $1, $2, deployment.id,
				CASE WHEN count(*) OVER () > 1 THEN 'AMBIGUOUS' ELSE 'MATCHED' END,
				'Grafana alert overlaps bounded deployment window'
			FROM deployment_events deployment
			WHERE deployment.project_id = $1 AND deployment.service_id = $3 AND deployment.environment = $4
			  AND deployment.started_at <= $5::timestamptz + interval '30 minutes'
			  AND COALESCE(deployment.finished_at, deployment.started_at) >= $5::timestamptz - interval '30 minutes'
			ORDER BY deployment.started_at DESC LIMIT 100
			ON CONFLICT (incident_id, deployment_event_id) DO UPDATE
			SET match_status = EXCLUDED.match_status, match_reason = EXCLUDED.match_reason
		`, updated.ProjectID, incidentID, serviceID, environment, updated.StartsAt); err != nil {
			return GrafanaAlertResult{}, fmt.Errorf("link remapped deployment candidates: %w", err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM deployment_candidates WHERE incident_id = $1`, incidentID).Scan(&result.DeploymentCount); err != nil {
			return GrafanaAlertResult{}, fmt.Errorf("count remapped deployment candidates: %w", err)
		}
	} else {
		// Reuse an existing investigation for resolved alerts, but never create one.
		// Snapshot validation also prevents remapping its historical evidence to another entity.
		err := tx.QueryRowContext(ctx, `SELECT id::text FROM investigations WHERE incident_id = $1 ORDER BY attempt DESC LIMIT 1`, incidentID).Scan(&result.InvestigationID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return GrafanaAlertResult{}, fmt.Errorf("read resolved Grafana investigation: %w", err)
		}
	}
	if result.InvestigationID != "" {
		if _, _, err := persistGrafanaAlertEvidence(ctx, tx, result.Alert.ID, GrafanaAlertEvidenceContext{InvestigationID: result.InvestigationID, CollectedAt: time.Now().UTC()}, filter); err != nil {
			return GrafanaAlertResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return GrafanaAlertResult{}, fmt.Errorf("commit Grafana alert remapping: %w", err)
	}
	return result, nil
}

func (repository *Postgres) IngestGrafanaAlerts(
	ctx context.Context,
	inputs []GrafanaAlertInput,
	requestID string,
	filter *redact.Filter,
) ([]GrafanaAlertResult, error) {
	if filter == nil {
		return nil, redact.ErrUnsafeOutput
	}
	if len(inputs) == 0 || len(inputs) > 100 || !validRequestID(requestID) {
		return nil, ErrInvalidInput
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin Grafana alert ingestion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	results := make([]GrafanaAlertResult, 0, len(inputs))
	for _, input := range inputs {
		result, err := ingestOneGrafanaAlert(ctx, tx, input, requestID)
		if err != nil {
			return nil, err
		}
		// Snapshot each item before a later alert in this batch changes its canonical state.
		if result.InvestigationID != "" {
			if _, _, err := persistGrafanaAlertEvidence(ctx, tx, result.Alert.ID, GrafanaAlertEvidenceContext{InvestigationID: result.InvestigationID, CollectedAt: time.Now().UTC()}, filter); err != nil {
				return nil, err
			}
		}
		results = append(results, result)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit Grafana alert ingestion: %w", err)
	}
	return results, nil
}

func ingestOneGrafanaAlert(
	ctx context.Context,
	tx *sql.Tx,
	input GrafanaAlertInput,
	requestID string,
) (GrafanaAlertResult, error) {
	if strings.TrimSpace(input.ProjectSlug) == "" || strings.TrimSpace(input.Fingerprint) == "" ||
		strings.TrimSpace(input.Summary) == "" || input.StartsAt.IsZero() ||
		(input.Status != "FIRING" && input.Status != "RESOLVED") {
		return GrafanaAlertResult{}, ErrInvalidInput
	}
	var projectID string
	if err := tx.QueryRowContext(ctx, `
		SELECT id::text FROM projects WHERE slug = $1 AND deleted_at IS NULL
	`, input.ProjectSlug).Scan(&projectID); errors.Is(err, sql.ErrNoRows) {
		return GrafanaAlertResult{}, ErrNotFound
	} else if err != nil {
		return GrafanaAlertResult{}, fmt.Errorf("resolve Grafana project: %w", err)
	}
	serviceID := ""
	environment := ""
	matched := false
	if input.ServiceSlug != "" && input.Environment != "" && validGrafanaEnvironment(input.Environment) {
		err := tx.QueryRowContext(ctx, `
			SELECT id::text FROM services WHERE project_id = $1 AND slug = $2 AND deleted_at IS NULL
		`, projectID, input.ServiceSlug).Scan(&serviceID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return GrafanaAlertResult{}, fmt.Errorf("resolve Grafana service: %w", err)
		}
		matched = err == nil
		if matched {
			environment = input.Environment
		}
	}
	labels, err := normalizedJSON(input.Labels, `{}`)
	if err != nil {
		return GrafanaAlertResult{}, err
	}
	annotations, err := normalizedJSON(input.Annotations, `{}`)
	if err != nil {
		return GrafanaAlertResult{}, err
	}
	payload, err := normalizedJSON(input.RedactedPayload, `{}`)
	if err != nil {
		return GrafanaAlertResult{}, err
	}
	payloadHashValue := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(payloadHashValue[:])
	startedAt := domain.NormalizeTime(input.StartsAt)
	lockKey := projectID + ":" + input.Fingerprint
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return GrafanaAlertResult{}, fmt.Errorf("lock Grafana fingerprint window: %w", err)
	}
	alert, err := scanAlert(tx.QueryRowContext(ctx, `
		SELECT `+alertColumns+` FROM alerts
		WHERE project_id = $1 AND fingerprint = $2
		  AND starts_at BETWEEN $3::timestamptz - interval '5 minutes' AND $3::timestamptz + interval '5 minutes'
		ORDER BY abs(extract(epoch FROM starts_at - $3::timestamptz)), starts_at
		LIMIT 1 FOR UPDATE
	`, projectID, input.Fingerprint, startedAt))
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return GrafanaAlertResult{}, fmt.Errorf("find Grafana alert fingerprint window: %w", err)
	}
	if created {
		alert, err = scanAlert(tx.QueryRowContext(ctx, `
			INSERT INTO alerts (
				project_id, service_id, environment, fingerprint, fingerprint_version, idempotency_key, status,
				severity, summary, starts_at, ends_at, labels, annotations, redacted_payload,
				source_reference, source_timezone, source_time_text
			) VALUES ($1, NULLIF($2, '')::uuid, NULLIF($3, ''), $4, $5, $6, $7, $8, $9,
				$10, $11, $12::jsonb, $13::jsonb, $14::jsonb, $15, NULLIF($16, ''), NULLIF($17, ''))
			RETURNING `+alertColumns,
			projectID, serviceID, environment, input.Fingerprint, input.FingerprintVersion,
			"grafana:"+input.Fingerprint+":"+startedAt.Format(time.RFC3339Nano),
			input.Status, input.Severity, input.Summary, startedAt, normalizeOptionalTime(input.EndsAt),
			string(labels), string(annotations), string(payload), input.SourceReference,
			input.SourceTimezone, input.SourceTimeText,
		))
		if err != nil {
			return GrafanaAlertResult{}, fmt.Errorf("create Grafana alert: %w", err)
		}
	} else {
		_, err = tx.ExecContext(ctx, `
			UPDATE alerts SET service_id = NULLIF($2, '')::uuid, environment = NULLIF($3, ''),
				status = $4, severity = $5, summary = $6, starts_at = LEAST(starts_at, $14), ends_at = $7,
				labels = $8::jsonb, annotations = $9::jsonb, redacted_payload = $10::jsonb,
				source_reference = $11, source_timezone = NULLIF($12, ''), source_time_text = NULLIF($13, '')
			WHERE id = $1
		`, alert.ID, serviceID, environment, input.Status, input.Severity, input.Summary,
			normalizeOptionalTime(input.EndsAt), string(labels), string(annotations), string(payload),
			input.SourceReference, input.SourceTimezone, input.SourceTimeText, startedAt)
		if err != nil {
			return GrafanaAlertResult{}, fmt.Errorf("update Grafana alert state: %w", err)
		}
		if serviceID != "" {
			alert.ServiceID = &serviceID
		} else {
			alert.ServiceID = nil
		}
		if environment != "" {
			alert.Environment = &environment
		} else {
			alert.Environment = nil
		}
		alert.Status, alert.Severity, alert.Summary, alert.EndsAt = input.Status, input.Severity, input.Summary, input.EndsAt
		alert.Labels, alert.Annotations, alert.RedactedPayload = labels, annotations, payload
	}
	alertID := alert.ID
	var incidentID string
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM incidents WHERE alert_id = $1`, alertID).Scan(&incidentID)
	if errors.Is(err, sql.ErrNoRows) {
		incidentStatus := "OPEN"
		var endedAt any
		if input.Status == "RESOLVED" {
			incidentStatus = "RESOLVED"
			endedAt = normalizeOptionalTime(input.EndsAt)
			if endedAt == nil {
				endedAt = time.Now().UTC()
			}
		}
		err = tx.QueryRowContext(ctx, `
			INSERT INTO incidents (project_id, alert_id, service_id, status, severity, summary, environment, started_at, ended_at, labels)
			VALUES ($1, $2, NULLIF($3, '')::uuid, $4, $5, $6, NULLIF($7, ''), $8, $9, $10::jsonb)
			RETURNING id::text
		`, projectID, alertID, serviceID, incidentStatus, input.Severity, input.Summary, environment,
			startedAt, endedAt, string(labels)).Scan(&incidentID)
		if err != nil {
			return GrafanaAlertResult{}, fmt.Errorf("create Grafana incident: %w", err)
		}
	} else if err != nil {
		return GrafanaAlertResult{}, fmt.Errorf("resolve Grafana incident: %w", err)
	} else {
		incidentStatus := "OPEN"
		var endedAt any
		if input.Status == "RESOLVED" {
			incidentStatus = "RESOLVED"
			endedAt = normalizeOptionalTime(input.EndsAt)
			if endedAt == nil {
				endedAt = time.Now().UTC()
			}
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE incidents SET service_id = NULLIF($2, '')::uuid, environment = NULLIF($3, ''),
				status = $4, severity = $5, summary = $6, ended_at = $7, labels = $8::jsonb
			WHERE id = $1
		`, incidentID, serviceID, environment, incidentStatus, input.Severity, input.Summary, endedAt, string(labels)); err != nil {
			return GrafanaAlertResult{}, fmt.Errorf("update Grafana incident: %w", err)
		}
	}
	matchState := "MATCHED"
	if !matched {
		matchState = "NEEDS_MAPPING"
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO alert_deliveries (
			project_id, alert_id, request_id, delivery_status, mapping_status, payload_hash, redacted_payload, received_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, now())
	`, projectID, alertID, requestID, input.Status, matchState, payloadHash, string(payload)); err != nil {
		return GrafanaAlertResult{}, fmt.Errorf("record Grafana alert delivery: %w", err)
	}
	result := GrafanaAlertResult{Alert: alert, IncidentID: incidentID, MatchState: matchState, Created: created, Duplicate: !created}
	if matched {
		var investigationID string
		err := tx.QueryRowContext(ctx, `
			SELECT id::text FROM investigations WHERE incident_id = $1 ORDER BY attempt DESC LIMIT 1
		`, incidentID).Scan(&investigationID)
		if err == nil {
			result.InvestigationID = investigationID
		} else if !errors.Is(err, sql.ErrNoRows) {
			return GrafanaAlertResult{}, fmt.Errorf("read Grafana investigation: %w", err)
		}
	}
	if matched && input.Status == "FIRING" {
		var investigationID string
		err := tx.QueryRowContext(ctx, `
			SELECT id::text FROM investigations WHERE incident_id = $1 ORDER BY attempt DESC LIMIT 1
		`, incidentID).Scan(&investigationID)
		if errors.Is(err, sql.ErrNoRows) {
			err = tx.QueryRowContext(ctx, `
				INSERT INTO investigations (incident_id, service_id, environment)
				VALUES ($1, $2, $3) RETURNING id::text
			`, incidentID, serviceID, environment).Scan(&investigationID)
			if err == nil {
				_, err = tx.ExecContext(ctx, `
					INSERT INTO investigation_transition_audits (investigation_id, from_status, to_status, version)
					VALUES ($1, NULL, 'RECEIVED', 1)
				`, investigationID)
			}
		}
		if err != nil {
			return GrafanaAlertResult{}, fmt.Errorf("create or find Grafana investigation: %w", err)
		}
		result.InvestigationID = investigationID
		rows, err := tx.QueryContext(ctx, `
			SELECT id::text FROM deployment_events
			WHERE project_id = $1 AND service_id = $2 AND environment = $3
			  AND started_at <= $4::timestamptz + interval '30 minutes'
			  AND COALESCE(finished_at, started_at) >= $4::timestamptz - interval '30 minutes'
			ORDER BY started_at DESC LIMIT 100
		`, projectID, serviceID, environment, startedAt)
		if err != nil {
			return GrafanaAlertResult{}, fmt.Errorf("query Grafana deployment candidates: %w", err)
		}
		var deploymentIDs []string
		for rows.Next() {
			var deploymentID string
			if err := rows.Scan(&deploymentID); err != nil {
				rows.Close()
				return GrafanaAlertResult{}, fmt.Errorf("scan Grafana deployment candidate: %w", err)
			}
			deploymentIDs = append(deploymentIDs, deploymentID)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return GrafanaAlertResult{}, fmt.Errorf("read Grafana deployment candidates: %w", err)
		}
		rows.Close()
		matchStatus := "MATCHED"
		if len(deploymentIDs) == 0 {
			matchStatus = "MISSING"
		} else if len(deploymentIDs) > 1 {
			matchStatus = "AMBIGUOUS"
		}
		for _, deploymentID := range deploymentIDs {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO deployment_candidates (project_id, incident_id, deployment_event_id, match_status, match_reason)
				VALUES ($1, $2, $3, $4, $5) ON CONFLICT (incident_id, deployment_event_id)
				DO UPDATE SET match_status = EXCLUDED.match_status, match_reason = EXCLUDED.match_reason
			`, projectID, incidentID, deploymentID, matchStatus, "Grafana alert overlaps bounded deployment window"); err != nil {
				return GrafanaAlertResult{}, fmt.Errorf("save Grafana deployment candidate: %w", err)
			}
		}
		result.DeploymentCount = len(deploymentIDs)
	}
	return result, nil
}

func validRequestID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("._:-", character)) {
			return false
		}
	}
	return true
}

func validGrafanaEnvironment(value string) bool {
	if len(value) == 0 || len(value) > 32 || !(value[0] >= 'a' && value[0] <= 'z' || value[0] >= '0' && value[0] <= '9') {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	return true
}
