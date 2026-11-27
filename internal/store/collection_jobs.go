package store

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"time"

	"github.com/Weiki886/relythra/internal/domain"
)

const (
	collectionJobMaxBatchSize  = 100
	collectionJobMaxLease      = time.Hour
	collectionJobMaxRetryDelay = 24 * time.Hour
	collectionJobMaxAttempts   = 5
)

var collectionJobErrorCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// InvestigationCollectionJob is an in-memory claim. LeaseToken is a bearer
// capability and must never be logged or exposed by an API.
type InvestigationCollectionJob struct {
	ID              string
	InvestigationID string
	AttemptCount    int
	LeaseToken      string
}

// ClaimInvestigationCollectionJobs claims a bounded batch without waiting for
// rows held by other consumers. Expired leases are reclaimable; attempts are
// incremented at claim time, so process crashes count toward the retry limit.
func (repository *Postgres) ClaimInvestigationCollectionJobs(
	ctx context.Context,
	limit int,
	lease time.Duration,
) ([]InvestigationCollectionJob, error) {
	if limit < 1 || limit > collectionJobMaxBatchSize || lease < time.Microsecond || lease > collectionJobMaxLease {
		return nil, ErrInvalidInput
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin collection job claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		WITH exhausted AS (
			SELECT id
			FROM investigation_collection_jobs
			WHERE status='RUNNING' AND locked_until <= now() AND attempt_count >= $1
			ORDER BY locked_until, created_at, id
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		UPDATE investigation_collection_jobs jobs
		SET status='FAILED', locked_until=NULL, lease_token=NULL, last_error_code='lease_expired'
		FROM exhausted
		WHERE jobs.id=exhausted.id
	`, collectionJobMaxAttempts, collectionJobMaxBatchSize); err != nil {
		return nil, fmt.Errorf("fail exhausted collection job leases: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
		WITH candidates AS (
			SELECT id
			FROM investigation_collection_jobs
			WHERE attempt_count < $3
			  AND ((status='PENDING' AND available_at <= now())
			    OR (status='RUNNING' AND locked_until <= now()))
			ORDER BY available_at, created_at, id
			FOR UPDATE SKIP LOCKED
			LIMIT $1
		)
		UPDATE investigation_collection_jobs jobs
		SET status='RUNNING', attempt_count=jobs.attempt_count+1,
			available_at=now(), locked_until=now()+($2::bigint * interval '1 microsecond'),
			lease_token=gen_random_uuid(),
			last_error_code=CASE WHEN jobs.status='RUNNING' THEN 'lease_expired' ELSE jobs.last_error_code END
		FROM candidates
		WHERE jobs.id=candidates.id
		RETURNING jobs.id::text, jobs.investigation_id::text, jobs.attempt_count, jobs.lease_token::text
	`, limit, lease.Microseconds(), collectionJobMaxAttempts)
	if err != nil {
		return nil, fmt.Errorf("claim investigation collection jobs: %w", err)
	}
	jobs := make([]InvestigationCollectionJob, 0, limit)
	for rows.Next() {
		var job InvestigationCollectionJob
		if err := rows.Scan(&job.ID, &job.InvestigationID, &job.AttemptCount, &job.LeaseToken); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan claimed investigation collection job: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("read claimed investigation collection jobs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close claimed investigation collection jobs: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit investigation collection job claim: %w", err)
	}
	return jobs, nil
}

// CompleteInvestigationCollectionJob completes only the active claim identified
// by leaseToken. A false result means the token was stale or the row is terminal.
func (repository *Postgres) CompleteInvestigationCollectionJob(
	ctx context.Context,
	jobID string,
	leaseToken string,
) (bool, error) {
	if !domain.IsID(jobID) || !domain.IsID(leaseToken) {
		return false, ErrInvalidInput
	}
	result, err := repository.db.ExecContext(ctx, `
		UPDATE investigation_collection_jobs
		SET status='COMPLETED', locked_until=NULL, lease_token=NULL, last_error_code=NULL
		WHERE id=$1 AND status='RUNNING' AND lease_token=$2 AND locked_until > now()
	`, jobID, leaseToken)
	if err != nil {
		return false, fmt.Errorf("complete investigation collection job: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read completed collection job result: %w", err)
	}
	return changed == 1, nil
}

// RetryInvestigationCollectionJob stores only a stable error code. A retry is
// scheduled with a caller-provided bounded delay; exhausted attempts become
// terminal and cannot be resurrected by a late Worker.
func (repository *Postgres) RetryInvestigationCollectionJob(
	ctx context.Context,
	jobID string,
	leaseToken string,
	errorCode string,
	delay time.Duration,
) (bool, error) {
	if !domain.IsID(jobID) || !domain.IsID(leaseToken) || !collectionJobErrorCodePattern.MatchString(errorCode) || delay < 0 || (delay > 0 && delay < time.Microsecond) || delay > collectionJobMaxRetryDelay {
		return false, ErrInvalidInput
	}
	var status string
	err := repository.db.QueryRowContext(ctx, `
		UPDATE investigation_collection_jobs
		SET status=CASE WHEN attempt_count >= $4 THEN 'FAILED' ELSE 'PENDING' END,
			available_at=CASE WHEN attempt_count >= $4 THEN available_at ELSE now()+($5::bigint * interval '1 microsecond') END,
			locked_until=NULL, lease_token=NULL, last_error_code=$3
		WHERE id=$1 AND status='RUNNING' AND lease_token=$2 AND locked_until > now()
		RETURNING status
	`, jobID, leaseToken, errorCode, collectionJobMaxAttempts, delay.Microseconds()).Scan(&status)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reschedule investigation collection job: %w", err)
	}
	return status == "FAILED", nil
}
