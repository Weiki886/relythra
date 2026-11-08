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
	"github.com/jackc/pgx/v5/pgconn"
)

type Postgres struct {
	db *sql.DB
}

func NewPostgres(db *sql.DB) *Postgres {
	return &Postgres{db: db}
}

type CreateDeploymentEventInput struct {
	ProjectID       string
	ServiceID       string
	ReleaseID       string
	Environment     string
	SourceSystem    string
	IdempotencyKey  string
	RequestID       string
	Status          string
	StartedAt       time.Time
	FinishedAt      *time.Time
	Version         string
	CommitSHA       string
	ImageDigest     string
	InstanceCount   int
	SourceReference string
	SourceTimezone  string
	SourceTimeText  string
	Metadata        json.RawMessage
}

type DeploymentEvent struct {
	ID                string          `json:"id"`
	ProjectID         string          `json:"project_id"`
	ServiceID         string          `json:"service_id"`
	ReleaseID         string          `json:"release_id"`
	Environment       string          `json:"environment"`
	SourceSystem      string          `json:"source_system"`
	IdempotencyKey    string          `json:"idempotency_key"`
	Status            string          `json:"status"`
	StartedAt         time.Time       `json:"started_at"`
	FinishedAt        *time.Time      `json:"finished_at"`
	Version           string          `json:"version"`
	CommitSHA         string          `json:"commit_sha"`
	ImageDigest       string          `json:"image_digest"`
	InstanceCount     int             `json:"instance_count"`
	SourceReference   string          `json:"source_reference"`
	SourceTimezone    string          `json:"source_timezone"`
	SourceTimeText    string          `json:"source_time_text"`
	Metadata          json.RawMessage `json:"metadata"`
	EventVersion      int64           `json:"event_version"`
	SourceConsistency string          `json:"source_consistency"`
	SourceConflicts   json.RawMessage `json:"source_conflicts"`
}

func (repository *Postgres) ClaimDeploymentWebhookSignature(
	ctx context.Context,
	digest []byte,
	expiresAt time.Time,
) (bool, error) {
	if len(digest) != 32 || expiresAt.IsZero() {
		return false, ErrInvalidInput
	}
	if _, err := repository.db.ExecContext(ctx, `
		DELETE FROM deployment_webhook_signatures WHERE expires_at < now() - interval '1 minute'
	`); err != nil {
		return false, fmt.Errorf("prune expired deployment webhook signatures: %w", err)
	}
	var claimed bool
	if err := repository.db.QueryRowContext(ctx, `
		INSERT INTO deployment_webhook_signatures (signature_digest, expires_at)
		VALUES ($1, $2)
		ON CONFLICT (signature_digest) DO NOTHING
		RETURNING true
	`, digest, expiresAt.UTC()).Scan(&claimed); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("claim deployment webhook signature: %w", err)
	}
	return claimed, nil
}

func (repository *Postgres) CreateDeploymentEvent(
	ctx context.Context,
	input CreateDeploymentEventInput,
) (DeploymentEvent, bool, error) {
	for _, id := range []string{input.ProjectID, input.ServiceID, input.ReleaseID} {
		if !domain.IsID(id) {
			return DeploymentEvent{}, false, fmt.Errorf("%w: invalid UUID", ErrInvalidInput)
		}
	}
	if err := validateOptionalTimeRange(input.StartedAt, input.FinishedAt); err != nil {
		return DeploymentEvent{}, false, err
	}
	metadata, err := normalizedJSON(input.Metadata, `{}`)
	if err != nil {
		return DeploymentEvent{}, false, err
	}

	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return DeploymentEvent{}, false, fmt.Errorf("begin deployment event transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var releaseVersion, releaseCommit, releaseDigest string
	if err := tx.QueryRowContext(ctx, `
		SELECT version, commit_sha, COALESCE(image_digest, '')
		FROM releases
		WHERE id = $1 AND service_id = $2 AND project_id = $3
	`, input.ReleaseID, input.ServiceID, input.ProjectID).Scan(&releaseVersion, &releaseCommit, &releaseDigest); errors.Is(err, sql.ErrNoRows) {
		return DeploymentEvent{}, false, ErrInvalidInput
	} else if err != nil {
		return DeploymentEvent{}, false, fmt.Errorf("validate deployment release: %w", err)
	}
	conflicts := make([]string, 0, 3)
	if input.Version != releaseVersion {
		conflicts = append(conflicts, "version")
	}
	if input.CommitSHA != releaseCommit {
		conflicts = append(conflicts, "commit_sha")
	}
	if input.ImageDigest != "" && releaseDigest != "" && input.ImageDigest != releaseDigest {
		conflicts = append(conflicts, "image_digest")
	}
	conflictJSON, err := json.Marshal(conflicts)
	if err != nil {
		return DeploymentEvent{}, false, fmt.Errorf("encode deployment source conflicts: %w", err)
	}
	consistency := "MATCHED"
	if len(conflicts) > 0 {
		consistency = "SOURCE_CONFLICT"
	} else if input.ImageDigest == "" || releaseDigest == "" {
		consistency = "UNVERIFIED"
	}

	const insert = `
		INSERT INTO deployment_events (
			project_id, service_id, release_id, environment, source_system,
			idempotency_key, status, started_at, finished_at, version, commit_sha,
			image_digest, instance_count, source_reference, source_timezone,
			source_time_text, metadata, source_consistency, source_conflicts
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
			NULLIF($15, ''), NULLIF($16, ''), $17::jsonb, $18, $19::jsonb
		)
		ON CONFLICT (service_id, environment, source_system, idempotency_key)
		DO NOTHING
		RETURNING ` + deploymentColumns

	event, err := scanDeploymentEvent(tx.QueryRowContext(
		ctx,
		insert,
		input.ProjectID,
		input.ServiceID,
		input.ReleaseID,
		input.Environment,
		input.SourceSystem,
		input.IdempotencyKey,
		input.Status,
		domain.NormalizeTime(input.StartedAt),
		normalizeOptionalTime(input.FinishedAt),
		input.Version,
		input.CommitSHA,
		nullableString(input.ImageDigest),
		input.InstanceCount,
		input.SourceReference,
		input.SourceTimezone,
		input.SourceTimeText,
		string(metadata),
		consistency,
		string(conflictJSON),
	))
	created := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return DeploymentEvent{}, false, fmt.Errorf("insert deployment event: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		event, err = scanDeploymentEvent(tx.QueryRowContext(ctx, `
			SELECT `+deploymentColumns+`
			FROM deployment_events
			WHERE service_id = $1
			  AND environment = $2
			  AND source_system = $3
			  AND idempotency_key = $4
		`, input.ServiceID, input.Environment, input.SourceSystem, input.IdempotencyKey))
		if errors.Is(err, sql.ErrNoRows) {
			return DeploymentEvent{}, false, ErrConflict
		}
		if err != nil {
			return DeploymentEvent{}, false, fmt.Errorf("read existing deployment event: %w", err)
		}
		if event.ReleaseID != input.ReleaseID || event.Version != input.Version || event.CommitSHA != input.CommitSHA || event.ImageDigest != input.ImageDigest || !event.StartedAt.Equal(domain.NormalizeTime(input.StartedAt)) {
			return DeploymentEvent{}, false, ErrConflict
		}
	}
	if created {
		requestID := input.RequestID
		if requestID == "" {
			requestID = input.IdempotencyKey
		}
		actor := input.SourceSystem
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO deployment_event_updates (
				deployment_event_id, event_version, actor, request_id, action,
				reason, before_state, after_state, occurred_at
			) VALUES ($1, 1, $2, $3, 'CREATED', 'deployment event received', '{}'::jsonb, $4::jsonb, now())
		`, event.ID, actor, requestID, deploymentStateJSON(event)); err != nil {
			return DeploymentEvent{}, false, fmt.Errorf("record deployment event creation: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return DeploymentEvent{}, false, fmt.Errorf("commit deployment event transaction: %w", err)
	}
	return event, created, nil
}

type UpdateDeploymentEventInput struct {
	ExpectedVersion int64
	Actor           string
	RequestID       string
	Reason          string
	Status          string
	FinishedAt      *time.Time
	ReleaseID       string
	Version         string
	CommitSHA       string
	ImageDigest     string
	InstanceCount   int
	StartedAt       *time.Time
	SourceReference string
}

func (repository *Postgres) UpdateDeploymentEvent(
	ctx context.Context,
	id string,
	input UpdateDeploymentEventInput,
) (DeploymentEvent, error) {
	if !domain.IsID(id) || input.ExpectedVersion < 1 || strings.TrimSpace(input.Actor) == "" ||
		strings.TrimSpace(input.RequestID) == "" || strings.TrimSpace(input.Reason) == "" {
		return DeploymentEvent{}, fmt.Errorf("%w: invalid deployment update", ErrInvalidInput)
	}

	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return DeploymentEvent{}, fmt.Errorf("begin deployment update transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, err := scanDeploymentEvent(tx.QueryRowContext(ctx, `
		SELECT `+deploymentColumns+`
		FROM deployment_events
		WHERE id = $1
		FOR UPDATE
	`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return DeploymentEvent{}, ErrNotFound
	}
	if err != nil {
		return DeploymentEvent{}, fmt.Errorf("read deployment event for update: %w", err)
	}
	if current.EventVersion != input.ExpectedVersion {
		return DeploymentEvent{}, ErrConflict
	}
	status := current.Status
	if input.Status != "" {
		status = input.Status
	}
	if status != current.Status {
		state := domain.DeploymentEvent{Status: domain.DeploymentStatus(current.Status)}
		if err := state.Transition(domain.DeploymentStatus(status)); err != nil {
			return DeploymentEvent{}, fmt.Errorf("%w: %v", ErrInvalidTransition, err)
		}
	}
	finishedAt := current.FinishedAt
	if input.FinishedAt != nil {
		finishedAt = input.FinishedAt
	}
	if terminalDeploymentStatus(status) && finishedAt == nil {
		return DeploymentEvent{}, fmt.Errorf("%w: finished_at is required for terminal deployment status", ErrInvalidInput)
	}
	startedAt := current.StartedAt
	if input.StartedAt != nil {
		startedAt = *input.StartedAt
	}
	if finishedAt != nil && finishedAt.Before(startedAt) {
		return DeploymentEvent{}, fmt.Errorf("%w: finished_at precedes started_at", ErrInvalidInput)
	}
	releaseID := current.ReleaseID
	if input.ReleaseID != "" {
		releaseID = input.ReleaseID
	}
	version := current.Version
	if input.Version != "" {
		version = input.Version
	}
	commitSHA := current.CommitSHA
	if input.CommitSHA != "" {
		commitSHA = input.CommitSHA
	}
	imageDigest := current.ImageDigest
	if input.ImageDigest != "" {
		imageDigest = input.ImageDigest
	}
	instanceCount := current.InstanceCount
	if input.InstanceCount != 0 {
		instanceCount = input.InstanceCount
	}
	sourceReference := current.SourceReference
	if input.SourceReference != "" {
		sourceReference = input.SourceReference
	}
	if !domain.IsID(releaseID) || strings.TrimSpace(version) == "" || strings.TrimSpace(commitSHA) == "" || instanceCount < 1 {
		return DeploymentEvent{}, fmt.Errorf("%w: corrected deployment facts are invalid", ErrInvalidInput)
	}
	var releaseVersion, releaseCommit, releaseDigest string
	if err := tx.QueryRowContext(ctx, `
		SELECT version, commit_sha, COALESCE(image_digest, '')
		FROM releases
		WHERE id = $1 AND service_id = $2 AND project_id = $3
	`, releaseID, current.ServiceID, current.ProjectID).Scan(&releaseVersion, &releaseCommit, &releaseDigest); errors.Is(err, sql.ErrNoRows) {
		return DeploymentEvent{}, ErrInvalidInput
	} else if err != nil {
		return DeploymentEvent{}, fmt.Errorf("validate corrected deployment release: %w", err)
	}
	conflicts := make([]string, 0, 3)
	if version != releaseVersion {
		conflicts = append(conflicts, "version")
	}
	if commitSHA != releaseCommit {
		conflicts = append(conflicts, "commit_sha")
	}
	if imageDigest != "" && releaseDigest != "" && imageDigest != releaseDigest {
		conflicts = append(conflicts, "image_digest")
	}
	conflictJSON, err := json.Marshal(conflicts)
	if err != nil {
		return DeploymentEvent{}, fmt.Errorf("encode corrected deployment conflicts: %w", err)
	}
	consistency := "MATCHED"
	if len(conflicts) > 0 {
		consistency = "SOURCE_CONFLICT"
	} else if imageDigest == "" || releaseDigest == "" {
		consistency = "UNVERIFIED"
	}

	corrected := status == current.Status &&
		!startedAt.Equal(current.StartedAt) || releaseID != current.ReleaseID || version != current.Version ||
		commitSHA != current.CommitSHA || imageDigest != current.ImageDigest || instanceCount != current.InstanceCount ||
		sourceReference != current.SourceReference
	finishedChanged := (finishedAt == nil) != (current.FinishedAt == nil) ||
		(finishedAt != nil && current.FinishedAt != nil && !finishedAt.Equal(*current.FinishedAt))
	if status == current.Status && !corrected && !finishedChanged {
		if err := tx.Commit(); err != nil {
			return DeploymentEvent{}, fmt.Errorf("commit unchanged deployment event: %w", err)
		}
		return current, nil
	}
	before := deploymentStateJSON(current)
	updated, err := scanDeploymentEvent(tx.QueryRowContext(ctx, `
		UPDATE deployment_events
		SET status = $2, started_at = $3, finished_at = $4, release_id = $5,
		    version = $6, commit_sha = $7, image_digest = NULLIF($8, ''),
		    instance_count = $9, source_reference = $10, event_version = event_version + 1,
		    source_consistency = $11, source_conflicts = $12::jsonb
		WHERE id = $1
		RETURNING `+deploymentColumns,
		id, status, domain.NormalizeTime(startedAt), normalizeOptionalTime(finishedAt), releaseID,
		version, commitSHA, imageDigest, instanceCount, sourceReference, consistency, string(conflictJSON)))
	if err != nil {
		return DeploymentEvent{}, fmt.Errorf("update deployment event: %w", err)
	}
	action := "UPDATED"
	if corrected {
		action = "CORRECTED"
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO deployment_event_updates (
			deployment_event_id, event_version, actor, request_id, action,
			reason, before_state, after_state, occurred_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, now())
	`, id, updated.EventVersion, input.Actor, input.RequestID, action, input.Reason, string(before), string(deploymentStateJSON(updated))); err != nil {
		return DeploymentEvent{}, fmt.Errorf("record deployment event update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return DeploymentEvent{}, fmt.Errorf("commit deployment event update: %w", err)
	}
	return updated, nil
}

type DeploymentCandidateQuery struct {
	ProjectID   string
	ServiceID   string
	Environment string
	Start       time.Time
	End         time.Time
	Limit       int
}

func (repository *Postgres) FindDeploymentCandidates(
	ctx context.Context,
	query DeploymentCandidateQuery,
) ([]DeploymentEvent, error) {
	if !domain.IsID(query.ProjectID) || !domain.IsID(query.ServiceID) || query.Environment == "" ||
		query.Limit < 1 || query.Limit > 100 {
		return nil, fmt.Errorf("%w: invalid deployment candidate query", ErrInvalidInput)
	}
	if err := domain.ValidateTimeRange(query.Start, query.End); err != nil {
		return nil, fmt.Errorf("%w: invalid deployment candidate time window", ErrInvalidInput)
	}
	if query.End.Sub(query.Start) > 24*time.Hour {
		return nil, fmt.Errorf("%w: deployment candidate window exceeds 24 hours", ErrInvalidInput)
	}
	rows, err := repository.db.QueryContext(ctx, `
		SELECT `+deploymentColumns+`
		FROM deployment_events
		WHERE project_id = $1 AND service_id = $2 AND environment = $3
		  AND started_at <= $5
		  AND COALESCE(finished_at, started_at) >= $4
		ORDER BY started_at, id
		LIMIT $6
	`, query.ProjectID, query.ServiceID, query.Environment, domain.NormalizeTime(query.Start), domain.NormalizeTime(query.End), query.Limit)
	if err != nil {
		return nil, fmt.Errorf("query deployment candidates: %w", err)
	}
	defer rows.Close()
	candidates := make([]DeploymentEvent, 0)
	for rows.Next() {
		candidate, scanErr := scanDeploymentEvent(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan deployment candidate: %w", scanErr)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate deployment candidates: %w", err)
	}
	return candidates, nil
}

func terminalDeploymentStatus(status string) bool {
	switch status {
	case string(domain.DeploymentSucceeded), string(domain.DeploymentFailed), string(domain.DeploymentRolledBack):
		return true
	default:
		return false
	}
}

func deploymentStateJSON(event DeploymentEvent) json.RawMessage {
	state, _ := json.Marshal(map[string]any{
		"status": event.Status, "event_version": event.EventVersion,
		"started_at": event.StartedAt, "finished_at": event.FinishedAt,
		"release_id": event.ReleaseID,
		"version":    event.Version, "commit_sha": event.CommitSHA,
		"image_digest": event.ImageDigest, "instance_count": event.InstanceCount,
		"source_reference":   event.SourceReference,
		"source_consistency": event.SourceConsistency, "source_conflicts": event.SourceConflicts,
	})
	return state
}

type CreateAlertInput struct {
	ProjectID       string
	ServiceID       string
	Environment     string
	Fingerprint     string
	IdempotencyKey  string
	Status          string
	Severity        string
	Summary         string
	StartsAt        time.Time
	EndsAt          *time.Time
	Labels          json.RawMessage
	Annotations     json.RawMessage
	RedactedPayload json.RawMessage
	SourceReference string
	SourceTimezone  string
	SourceTimeText  string
}

type Alert struct {
	ID                 string          `json:"id"`
	ProjectID          string          `json:"project_id"`
	ServiceID          *string         `json:"service_id"`
	Environment        *string         `json:"environment"`
	Fingerprint        string          `json:"fingerprint"`
	FingerprintVersion string          `json:"fingerprint_version"`
	EventVersion       int64           `json:"event_version"`
	IdempotencyKey     string          `json:"idempotency_key"`
	Status             string          `json:"status"`
	Severity           string          `json:"severity"`
	Summary            string          `json:"summary"`
	StartsAt           time.Time       `json:"starts_at"`
	EndsAt             *time.Time      `json:"ends_at"`
	Labels             json.RawMessage `json:"labels"`
	Annotations        json.RawMessage `json:"annotations"`
	RedactedPayload    json.RawMessage `json:"redacted_payload"`
	SourceReference    string          `json:"source_reference"`
	SourceTimezone     string          `json:"source_timezone"`
	SourceTimeText     string          `json:"source_time_text"`
}

func (repository *Postgres) CreateAlert(
	ctx context.Context,
	input CreateAlertInput,
) (Alert, bool, error) {
	if !domain.IsID(input.ProjectID) {
		return Alert{}, false, fmt.Errorf("%w: invalid project UUID", ErrInvalidInput)
	}
	if input.ServiceID != "" && !domain.IsID(input.ServiceID) {
		return Alert{}, false, fmt.Errorf("%w: invalid service UUID", ErrInvalidInput)
	}
	if err := validateOptionalTimeRange(input.StartsAt, input.EndsAt); err != nil {
		return Alert{}, false, err
	}
	labels, err := normalizedJSON(input.Labels, `{}`)
	if err != nil {
		return Alert{}, false, err
	}
	annotations, err := normalizedJSON(input.Annotations, `{}`)
	if err != nil {
		return Alert{}, false, err
	}
	redactedPayload, err := normalizedJSON(input.RedactedPayload, `{}`)
	if err != nil {
		return Alert{}, false, err
	}

	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Alert{}, false, fmt.Errorf("begin alert transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	alert, found, err := findAlertByKey(ctx, tx, input.ProjectID, input.IdempotencyKey)
	if err != nil {
		return Alert{}, false, err
	}
	if found {
		if err := tx.Commit(); err != nil {
			return Alert{}, false, fmt.Errorf("commit existing alert transaction: %w", err)
		}
		return alert, false, nil
	}

	const insert = `
		INSERT INTO alerts (
			project_id, service_id, environment, fingerprint, idempotency_key,
			status, severity, summary, starts_at, ends_at, labels, annotations,
			redacted_payload, source_reference, source_timezone, source_time_text
		) VALUES (
			$1, NULLIF($2, '')::uuid, NULLIF($3, ''), $4, $5, $6, $7, $8, $9,
			$10, $11::jsonb, $12::jsonb, $13::jsonb, $14, NULLIF($15, ''),
			NULLIF($16, '')
		)
		ON CONFLICT DO NOTHING
		RETURNING ` + alertColumns

	alert, err = scanAlert(tx.QueryRowContext(
		ctx,
		insert,
		input.ProjectID,
		input.ServiceID,
		input.Environment,
		input.Fingerprint,
		input.IdempotencyKey,
		input.Status,
		input.Severity,
		input.Summary,
		domain.NormalizeTime(input.StartsAt),
		normalizeOptionalTime(input.EndsAt),
		string(labels),
		string(annotations),
		string(redactedPayload),
		input.SourceReference,
		input.SourceTimezone,
		input.SourceTimeText,
	))
	created := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Alert{}, false, fmt.Errorf("insert alert: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		alert, found, err = findAlertByKey(ctx, tx, input.ProjectID, input.IdempotencyKey)
		if err != nil {
			return Alert{}, false, err
		}
		if !found {
			alert, found, err = findAlertByFingerprintWindow(
				ctx,
				tx,
				input.ProjectID,
				input.Fingerprint,
				domain.NormalizeTime(input.StartsAt),
			)
			if err != nil {
				return Alert{}, false, err
			}
		}
		if !found {
			return Alert{}, false, ErrConflict
		}
	}
	if err := tx.Commit(); err != nil {
		return Alert{}, false, fmt.Errorf("commit alert transaction: %w", err)
	}
	return alert, created, nil
}

func validateOptionalTimeRange(start time.Time, end *time.Time) error {
	endTime := start
	if end != nil {
		endTime = *end
	}
	if err := domain.ValidateTimeRange(start, endTime); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return nil
}

type Investigation struct {
	ID            string                     `json:"id"`
	IncidentID    string                     `json:"incident_id"`
	ServiceID     *string                    `json:"service_id"`
	Environment   *string                    `json:"environment"`
	Attempt       int                        `json:"attempt"`
	Version       int64                      `json:"version"`
	Status        domain.InvestigationStatus `json:"status"`
	CurrentStep   *string                    `json:"current_step"`
	Model         *string                    `json:"model"`
	PromptVersion *string                    `json:"prompt_version"`
	StartedAt     time.Time                  `json:"started_at"`
	CompletedAt   *time.Time                 `json:"completed_at"`
	CreatedAt     time.Time                  `json:"created_at"`
	UpdatedAt     time.Time                  `json:"updated_at"`
}

func (repository *Postgres) TransitionInvestigation(
	ctx context.Context,
	id string,
	expectedVersion int64,
	to domain.InvestigationStatus,
) (Investigation, error) {
	if !domain.IsID(id) {
		return Investigation{}, fmt.Errorf("%w: invalid investigation UUID", ErrInvalidInput)
	}

	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Investigation{}, fmt.Errorf("begin investigation transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var currentStatus string
	var currentVersion int64
	if err := tx.QueryRowContext(ctx, `
		SELECT status, version
		FROM investigations
		WHERE id = $1
		FOR UPDATE
	`, id).Scan(&currentStatus, &currentVersion); errors.Is(err, sql.ErrNoRows) {
		return Investigation{}, ErrNotFound
	} else if err != nil {
		return Investigation{}, fmt.Errorf("read investigation for transition: %w", err)
	}
	if currentVersion != expectedVersion {
		return Investigation{}, fmt.Errorf(
			"%w: investigation version is %d, expected %d",
			ErrConflict,
			currentVersion,
			expectedVersion,
		)
	}

	investigation := domain.Investigation{Status: domain.InvestigationStatus(currentStatus)}
	if !investigation.Status.Valid() {
		return Investigation{}, fmt.Errorf("%w: invalid persisted status", ErrInvalidTransition)
	}
	if err := investigation.Transition(to); err != nil {
		return Investigation{}, fmt.Errorf("%w: %v", ErrInvalidTransition, err)
	}

	var completedAt any
	if isTerminalInvestigation(to) {
		completedAt = time.Now().UTC()
	}
	updated, err := scanInvestigation(tx.QueryRowContext(ctx, `
		UPDATE investigations
		SET status = $2, version = version + 1, completed_at = $3
		WHERE id = $1
		RETURNING `+investigationColumns,
		id,
		to,
		completedAt,
	))
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) {
			switch pgError.Code {
			case "23514", "23001":
				return Investigation{}, fmt.Errorf("%w: %v", ErrInvalidTransition, err)
			case "40001", "40P01", "23505":
				return Investigation{}, fmt.Errorf("%w: %v", ErrConflict, err)
			}
		}
		return Investigation{}, fmt.Errorf("persist investigation transition: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Investigation{}, fmt.Errorf("commit investigation transition: %w", err)
	}
	return updated, nil
}

type Evidence struct {
	ID                string          `json:"id"`
	InvestigationID   string          `json:"investigation_id"`
	ToolCallID        *string         `json:"tool_call_id"`
	SourceType        string          `json:"source_type"`
	EntityType        string          `json:"entity_type"`
	EntityID          *string         `json:"entity_id"`
	ObservedStart     time.Time       `json:"observed_start"`
	ObservedEnd       time.Time       `json:"observed_end"`
	CollectedAt       *time.Time      `json:"collected_at"`
	QueryText         string          `json:"query_text"`
	RawReference      string          `json:"raw_reference"`
	QueryParameters   json.RawMessage `json:"query_parameters"`
	ValueSummary      json.RawMessage `json:"value_summary"`
	Completeness      string          `json:"completeness"`
	FreshnessSeconds  *int            `json:"freshness_seconds"`
	IndependenceGroup string          `json:"independence_group"`
	ContentHash       string          `json:"content_hash"`
	SourceTimezone    string          `json:"source_timezone"`
	SourceTimeText    string          `json:"source_time_text"`
	CreatedAt         time.Time       `json:"created_at"`
}

func (repository *Postgres) PersistEvidence(ctx context.Context, record evidence.Record) (Evidence, bool, error) {
	if err := evidence.Validate(record); err != nil {
		return Evidence{}, false, fmt.Errorf("%w: invalid normalized evidence", ErrInvalidInput)
	}
	if record.ToolCallID != nil {
		var belongsToInvestigation bool
		if err := repository.db.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM tool_calls WHERE id = $1 AND investigation_id = $2
			)
		`, *record.ToolCallID, record.InvestigationID).Scan(&belongsToInvestigation); err != nil {
			return Evidence{}, false, fmt.Errorf("validate evidence tool call: %w", err)
		}
		if !belongsToInvestigation {
			return Evidence{}, false, fmt.Errorf("%w: tool call belongs to another investigation", ErrInvalidInput)
		}
	}

	insert := `
		INSERT INTO evidence (
			investigation_id, tool_call_id, source_type, entity_type, entity_id,
			observed_start, observed_end, collected_at, query_text, raw_reference,
			query_parameters, value_summary, completeness, freshness_seconds,
			independence_group, content_hash, source_timezone, source_time_text
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), NULLIF($10, ''), $11::jsonb, $12::jsonb,
			$13, $14, $15, $16, NULLIF($17, ''), NULLIF($18, '')
		)
		ON CONFLICT (investigation_id, source_type, content_hash) DO NOTHING
		RETURNING ` + evidenceColumns
	item, err := scanEvidence(repository.db.QueryRowContext(ctx, insert,
		record.InvestigationID, nullableStringPointer(record.ToolCallID), record.SourceType,
		record.EntityType, nullableStringPointer(record.EntityID), domain.NormalizeTime(record.ObservedStart),
		domain.NormalizeTime(record.ObservedEnd), domain.NormalizeTime(record.CollectedAt), record.QueryText,
		record.RawReference, string(record.QueryParameters), string(record.ValueSummary), record.Completeness,
		record.FreshnessSeconds, record.IndependenceGroup, record.ContentHash, record.SourceTimezone, record.SourceTimeText,
	))
	if err == nil {
		return item, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Evidence{}, false, fmt.Errorf("persist evidence: %w", err)
	}

	item, err = scanEvidence(repository.db.QueryRowContext(ctx, `
		SELECT `+evidenceColumns+`
		FROM evidence
		WHERE investigation_id = $1 AND source_type = $2 AND content_hash = $3
	`, record.InvestigationID, record.SourceType, record.ContentHash))
	if errors.Is(err, sql.ErrNoRows) {
		return Evidence{}, false, ErrConflict
	}
	if err != nil {
		return Evidence{}, false, fmt.Errorf("read existing evidence: %w", err)
	}
	return item, false, nil
}

type Report struct {
	ID               string            `json:"id"`
	InvestigationID  string            `json:"investigation_id"`
	ResultStatus     string            `json:"result_status"`
	Confidence       string            `json:"confidence"`
	Summary          string            `json:"summary"`
	Recommendations  json.RawMessage   `json:"recommendations"`
	DataGaps         json.RawMessage   `json:"data_gaps"`
	Timeline         json.RawMessage   `json:"timeline"`
	GeneratedAt      time.Time         `json:"generated_at"`
	Evidence         []Evidence        `json:"evidence"`
	DeploymentEvents []DeploymentEvent `json:"deployment_events"`
}

func (repository *Postgres) GetReport(ctx context.Context, id string) (Report, error) {
	if !domain.IsID(id) {
		return Report{}, fmt.Errorf("%w: invalid report UUID", ErrInvalidInput)
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return Report{}, fmt.Errorf("begin report read transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var report Report
	var recommendations string
	var dataGaps string
	var timeline string
	var incidentID string
	err = tx.QueryRowContext(ctx, `
		SELECT
			report.id::text,
			report.investigation_id::text,
			report.result_status,
			report.confidence,
			report.summary,
			report.recommendations::text,
			report.data_gaps::text,
			report.timeline::text,
			report.generated_at,
			investigation.incident_id::text
		FROM reports report
		JOIN investigations investigation ON investigation.id = report.investigation_id
		WHERE report.id = $1
	`, id).Scan(
		&report.ID,
		&report.InvestigationID,
		&report.ResultStatus,
		&report.Confidence,
		&report.Summary,
		&recommendations,
		&dataGaps,
		&timeline,
		&report.GeneratedAt,
		&incidentID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Report{}, ErrNotFound
	}
	if err != nil {
		return Report{}, fmt.Errorf("read report: %w", err)
	}
	report.Recommendations = json.RawMessage(recommendations)
	report.DataGaps = json.RawMessage(dataGaps)
	report.Timeline = json.RawMessage(timeline)

	evidenceRows, err := tx.QueryContext(ctx, `
		SELECT `+evidenceColumns+`
		FROM evidence
		WHERE investigation_id = $1
		ORDER BY observed_start, created_at, id
	`, report.InvestigationID)
	if err != nil {
		return Report{}, fmt.Errorf("read report evidence: %w", err)
	}
	for evidenceRows.Next() {
		evidence, err := scanEvidence(evidenceRows)
		if err != nil {
			_ = evidenceRows.Close()
			return Report{}, fmt.Errorf("scan report evidence: %w", err)
		}
		report.Evidence = append(report.Evidence, evidence)
	}
	if err := evidenceRows.Err(); err != nil {
		_ = evidenceRows.Close()
		return Report{}, fmt.Errorf("iterate report evidence: %w", err)
	}
	_ = evidenceRows.Close()

	deploymentRows, err := tx.QueryContext(ctx, `
		SELECT `+prefixedDeploymentColumns("deployment")+`
		FROM deployment_candidates candidate
		JOIN deployment_events deployment
		  ON deployment.id = candidate.deployment_event_id
		WHERE candidate.incident_id = $1
		ORDER BY deployment.started_at DESC, deployment.id
	`, incidentID)
	if err != nil {
		return Report{}, fmt.Errorf("read report deployments: %w", err)
	}
	for deploymentRows.Next() {
		deployment, err := scanDeploymentEvent(deploymentRows)
		if err != nil {
			_ = deploymentRows.Close()
			return Report{}, fmt.Errorf("scan report deployment: %w", err)
		}
		report.DeploymentEvents = append(report.DeploymentEvents, deployment)
	}
	if err := deploymentRows.Err(); err != nil {
		_ = deploymentRows.Close()
		return Report{}, fmt.Errorf("iterate report deployments: %w", err)
	}
	_ = deploymentRows.Close()

	if err := tx.Commit(); err != nil {
		return Report{}, fmt.Errorf("commit report read transaction: %w", err)
	}
	return report, nil
}

func (repository *Postgres) GetEvidence(ctx context.Context, id string) (Evidence, error) {
	if !domain.IsID(id) {
		return Evidence{}, fmt.Errorf("%w: invalid evidence UUID", ErrInvalidInput)
	}
	evidence, err := scanEvidence(repository.db.QueryRowContext(ctx, `
		SELECT `+evidenceColumns+`
		FROM evidence
		WHERE id = $1
	`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Evidence{}, ErrNotFound
	}
	if err != nil {
		return Evidence{}, fmt.Errorf("read evidence: %w", err)
	}
	return evidence, nil
}

func (repository *Postgres) GetDeploymentEvent(
	ctx context.Context,
	id string,
) (DeploymentEvent, error) {
	if !domain.IsID(id) {
		return DeploymentEvent{}, fmt.Errorf("%w: invalid deployment UUID", ErrInvalidInput)
	}
	deployment, err := scanDeploymentEvent(repository.db.QueryRowContext(ctx, `
		SELECT `+deploymentColumns+`
		FROM deployment_events
		WHERE id = $1
	`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return DeploymentEvent{}, ErrNotFound
	}
	if err != nil {
		return DeploymentEvent{}, fmt.Errorf("read deployment event: %w", err)
	}
	return deployment, nil
}

const deploymentColumns = `
	id::text,
	project_id::text,
	service_id::text,
	release_id::text,
	environment,
	source_system,
	idempotency_key,
	status,
	started_at,
	finished_at,
	version,
	commit_sha,
	COALESCE(image_digest, ''),
	instance_count,
	source_reference,
	COALESCE(source_timezone, ''),
	COALESCE(source_time_text, ''),
	metadata::text,
	event_version,
	source_consistency,
	source_conflicts::text
`

func prefixedDeploymentColumns(prefix string) string {
	return prefix + ".id::text, " +
		prefix + ".project_id::text, " +
		prefix + ".service_id::text, " +
		prefix + ".release_id::text, " +
		prefix + ".environment, " +
		prefix + ".source_system, " +
		prefix + ".idempotency_key, " +
		prefix + ".status, " +
		prefix + ".started_at, " +
		prefix + ".finished_at, " +
		prefix + ".version, " +
		prefix + ".commit_sha, " +
		"COALESCE(" + prefix + ".image_digest, ''), " +
		prefix + ".instance_count, " +
		prefix + ".source_reference, " +
		"COALESCE(" + prefix + ".source_timezone, ''), " +
		"COALESCE(" + prefix + ".source_time_text, ''), " +
		prefix + ".metadata::text, " +
		prefix + ".event_version, " +
		prefix + ".source_consistency, " +
		prefix + ".source_conflicts::text"
}

type scanner interface {
	Scan(dest ...any) error
}

func scanDeploymentEvent(row scanner) (DeploymentEvent, error) {
	var deployment DeploymentEvent
	var finishedAt sql.NullTime
	var metadata string
	var sourceConflicts string
	err := row.Scan(
		&deployment.ID,
		&deployment.ProjectID,
		&deployment.ServiceID,
		&deployment.ReleaseID,
		&deployment.Environment,
		&deployment.SourceSystem,
		&deployment.IdempotencyKey,
		&deployment.Status,
		&deployment.StartedAt,
		&finishedAt,
		&deployment.Version,
		&deployment.CommitSHA,
		&deployment.ImageDigest,
		&deployment.InstanceCount,
		&deployment.SourceReference,
		&deployment.SourceTimezone,
		&deployment.SourceTimeText,
		&metadata,
		&deployment.EventVersion,
		&deployment.SourceConsistency,
		&sourceConflicts,
	)
	if err != nil {
		return DeploymentEvent{}, err
	}
	deployment.FinishedAt = nullTimePointer(finishedAt)
	deployment.Metadata = json.RawMessage(metadata)
	deployment.SourceConflicts = json.RawMessage(sourceConflicts)
	return deployment, nil
}

const alertColumns = `
	id::text,
	project_id::text,
	service_id::text,
	environment,
	fingerprint,
	fingerprint_version,
	event_version,
	idempotency_key,
	status,
	severity,
	summary,
	starts_at,
	ends_at,
	labels::text,
	annotations::text,
	redacted_payload::text,
	source_reference,
	COALESCE(source_timezone, ''),
	COALESCE(source_time_text, '')
`

func scanAlert(row scanner) (Alert, error) {
	var alert Alert
	var serviceID sql.NullString
	var environment sql.NullString
	var endsAt sql.NullTime
	var labels string
	var annotations string
	var redactedPayload string
	err := row.Scan(
		&alert.ID,
		&alert.ProjectID,
		&serviceID,
		&environment,
		&alert.Fingerprint,
		&alert.FingerprintVersion,
		&alert.EventVersion,
		&alert.IdempotencyKey,
		&alert.Status,
		&alert.Severity,
		&alert.Summary,
		&alert.StartsAt,
		&endsAt,
		&labels,
		&annotations,
		&redactedPayload,
		&alert.SourceReference,
		&alert.SourceTimezone,
		&alert.SourceTimeText,
	)
	if err != nil {
		return Alert{}, err
	}
	alert.ServiceID = nullStringPointer(serviceID)
	alert.Environment = nullStringPointer(environment)
	alert.EndsAt = nullTimePointer(endsAt)
	alert.Labels = json.RawMessage(labels)
	alert.Annotations = json.RawMessage(annotations)
	alert.RedactedPayload = json.RawMessage(redactedPayload)
	return alert, nil
}

func findAlertByKey(
	ctx context.Context,
	tx *sql.Tx,
	projectID string,
	idempotencyKey string,
) (Alert, bool, error) {
	alert, err := scanAlert(tx.QueryRowContext(ctx, `
		SELECT `+alertColumns+`
		FROM alerts
		WHERE project_id = $1 AND idempotency_key = $2
	`, projectID, idempotencyKey))
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, false, nil
	}
	if err != nil {
		return Alert{}, false, fmt.Errorf("read alert by idempotency key: %w", err)
	}
	return alert, true, nil
}

func findAlertByFingerprintWindow(
	ctx context.Context,
	tx *sql.Tx,
	projectID string,
	fingerprint string,
	startsAt time.Time,
) (Alert, bool, error) {
	alert, err := scanAlert(tx.QueryRowContext(ctx, `
		SELECT `+alertColumns+`
		FROM alerts
		WHERE project_id = $1 AND fingerprint = $2 AND starts_at = $3
	`, projectID, fingerprint, startsAt))
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, false, nil
	}
	if err != nil {
		return Alert{}, false, fmt.Errorf("read alert by fingerprint window: %w", err)
	}
	return alert, true, nil
}

const investigationColumns = `
	id::text,
	incident_id::text,
	service_id::text,
	environment,
	attempt,
	version,
	status,
	current_step,
	model,
	prompt_version,
	started_at,
	completed_at,
	created_at,
	updated_at
`

func scanInvestigation(row scanner) (Investigation, error) {
	var investigation Investigation
	var serviceID sql.NullString
	var environment sql.NullString
	var currentStep sql.NullString
	var model sql.NullString
	var promptVersion sql.NullString
	var completedAt sql.NullTime
	var status string
	err := row.Scan(
		&investigation.ID,
		&investigation.IncidentID,
		&serviceID,
		&environment,
		&investigation.Attempt,
		&investigation.Version,
		&status,
		&currentStep,
		&model,
		&promptVersion,
		&investigation.StartedAt,
		&completedAt,
		&investigation.CreatedAt,
		&investigation.UpdatedAt,
	)
	if err != nil {
		return Investigation{}, err
	}
	investigation.ServiceID = nullStringPointer(serviceID)
	investigation.Environment = nullStringPointer(environment)
	investigation.Status = domain.InvestigationStatus(status)
	investigation.CurrentStep = nullStringPointer(currentStep)
	investigation.Model = nullStringPointer(model)
	investigation.PromptVersion = nullStringPointer(promptVersion)
	investigation.CompletedAt = nullTimePointer(completedAt)
	return investigation, nil
}

const evidenceColumns = `
	id::text,
	investigation_id::text,
	tool_call_id::text,
	source_type,
	entity_type,
	entity_id,
	observed_start,
	observed_end,
	collected_at,
	COALESCE(query_text, ''),
	COALESCE(raw_reference, ''),
	query_parameters::text,
	value_summary::text,
	completeness,
	freshness_seconds,
	independence_group,
	content_hash,
	COALESCE(source_timezone, ''),
	COALESCE(source_time_text, ''),
	created_at
`

func scanEvidence(row scanner) (Evidence, error) {
	var evidence Evidence
	var toolCallID sql.NullString
	var entityID sql.NullString
	var valueSummary string
	var collectedAt sql.NullTime
	var queryParameters string
	var freshnessSeconds sql.NullInt64
	err := row.Scan(
		&evidence.ID,
		&evidence.InvestigationID,
		&toolCallID,
		&evidence.SourceType,
		&evidence.EntityType,
		&entityID,
		&evidence.ObservedStart,
		&evidence.ObservedEnd,
		&collectedAt,
		&evidence.QueryText,
		&evidence.RawReference,
		&queryParameters,
		&valueSummary,
		&evidence.Completeness,
		&freshnessSeconds,
		&evidence.IndependenceGroup,
		&evidence.ContentHash,
		&evidence.SourceTimezone,
		&evidence.SourceTimeText,
		&evidence.CreatedAt,
	)
	if err != nil {
		return Evidence{}, err
	}
	evidence.ToolCallID = nullStringPointer(toolCallID)
	evidence.EntityID = nullStringPointer(entityID)
	evidence.ValueSummary = json.RawMessage(valueSummary)
	evidence.QueryParameters = json.RawMessage(queryParameters)
	evidence.CollectedAt = nullTimePointer(collectedAt)
	if freshnessSeconds.Valid {
		value := int(freshnessSeconds.Int64)
		evidence.FreshnessSeconds = &value
	}
	return evidence, nil
}

func normalizedJSON(value json.RawMessage, fallback string) (json.RawMessage, error) {
	if len(value) == 0 {
		return json.RawMessage(fallback), nil
	}
	if !json.Valid(value) {
		return nil, fmt.Errorf("%w: malformed JSON", ErrInvalidInput)
	}
	return value, nil
}

func normalizeOptionalTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return domain.NormalizeTime(*value)
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableStringPointer(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullStringPointer(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}

func nullTimePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	return &value.Time
}

func isTerminalInvestigation(status domain.InvestigationStatus) bool {
	switch status {
	case domain.InvestigationCompleted,
		domain.InvestigationInsufficientEvidence,
		domain.InvestigationFailed:
		return true
	default:
		return false
	}
}
