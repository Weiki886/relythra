package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCollectionJobsClaimLeaseRetryAndCompletion(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "collection-lease")
	repository := NewPostgres(db)
	filter := mustGrafanaEvidenceFilter(t)
	investigationIDs := make([]string, 0, 2)
	for _, fingerprint := range []string{"collection-lease-a", "collection-lease-b"} {
		input := fixtureAlertInput(fixture, fingerprint)
		input.ProjectSlug = "collection-lease"
		result, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, fingerprint+"-request", filter)
		if err != nil {
			t.Fatalf("create queued investigation %s: %v", fingerprint, err)
		}
		investigationIDs = append(investigationIDs, result[0].InvestigationID)
	}

	first, err := repository.ClaimInvestigationCollectionJobs(ctx, 1, 30*time.Second)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim jobs=%+v err=%v, want one job", first, err)
	}
	second, err := repository.ClaimInvestigationCollectionJobs(ctx, 1, 30*time.Second)
	if err != nil || len(second) != 1 {
		t.Fatalf("second claim jobs=%+v err=%v, want one job", second, err)
	}
	if first[0].ID == second[0].ID || first[0].InvestigationID == second[0].InvestigationID {
		t.Fatalf("sequential consumers claimed same job: first=%+v second=%+v", first[0], second[0])
	}

	if _, err := db.ExecContext(ctx, `UPDATE investigation_collection_jobs SET locked_until=now()-interval '1 second' WHERE id=$1`, first[0].ID); err != nil {
		t.Fatalf("expire first lease: %v", err)
	}
	reclaimed, err := repository.ClaimInvestigationCollectionJobs(ctx, 1, 30*time.Second)
	if err != nil || len(reclaimed) != 1 {
		t.Fatalf("reclaim expired job=%+v err=%v, want one job", reclaimed, err)
	}
	if reclaimed[0].ID != first[0].ID || reclaimed[0].AttemptCount != 2 || reclaimed[0].LeaseToken == first[0].LeaseToken {
		t.Fatalf("reclaimed job=%+v, want same job, attempt 2 and a fresh lease token", reclaimed[0])
	}
	if completed, err := repository.CompleteInvestigationCollectionJob(ctx, first[0].ID, first[0].LeaseToken); completed || err != nil {
		t.Fatalf("complete with stale lease token completed=%v err=%v, want no-op", completed, err)
	}

	done, err := repository.CompleteInvestigationCollectionJob(ctx, reclaimed[0].ID, reclaimed[0].LeaseToken)
	if err != nil || !done {
		t.Fatalf("complete reclaimed job done=%v err=%v", done, err)
	}
	if done, err := repository.CompleteInvestigationCollectionJob(ctx, reclaimed[0].ID, reclaimed[0].LeaseToken); err != nil || done {
		t.Fatalf("complete terminal job done=%v err=%v, want idempotent false", done, err)
	}

	retried, err := repository.RetryInvestigationCollectionJob(ctx, second[0].ID, second[0].LeaseToken, "source_timeout", 2*time.Hour)
	if err != nil || retried {
		t.Fatalf("retry job terminal=%v err=%v, want scheduled retry", retried, err)
	}
	var status, errorCode string
	var attempt int
	var availableAt, lockedUntil *time.Time
	if err := db.QueryRowContext(ctx, `
		SELECT status, attempt_count, last_error_code, available_at, locked_until
		FROM investigation_collection_jobs WHERE id=$1
	`, second[0].ID).Scan(&status, &attempt, &errorCode, &availableAt, &lockedUntil); err != nil {
		t.Fatalf("read retried job: %v", err)
	}
	if status != "PENDING" || attempt != 1 || errorCode != "source_timeout" || availableAt == nil || availableAt.Before(time.Now().UTC().Add(119*time.Minute)) || lockedUntil != nil {
		t.Fatalf("retried job status=%s attempt=%d error=%s available=%v locked=%v", status, attempt, errorCode, availableAt, lockedUntil)
	}
	if jobs, err := repository.ClaimInvestigationCollectionJobs(ctx, 10, 30*time.Second); err != nil || len(jobs) != 0 {
		t.Fatalf("claim before retry time jobs=%+v err=%v, want no jobs", jobs, err)
	}
}

func TestCollectionJobsConcurrentClaimsAndRetryExhaustion(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "collection-concurrent")
	repository := NewPostgres(db)
	filter := mustGrafanaEvidenceFilter(t)
	for index := range 6 {
		input := fixtureAlertInput(fixture, fmt.Sprintf("collection-concurrent-%d", index))
		input.ProjectSlug = "collection-concurrent"
		if _, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, fmt.Sprintf("collection-concurrent-request-%d", index), filter); err != nil {
			t.Fatalf("create queued investigation %d: %v", index, err)
		}
	}

	const consumers = 6
	results := make(chan []InvestigationCollectionJob, consumers)
	errorsChannel := make(chan error, consumers)
	for range consumers {
		go func() {
			jobs, err := repository.ClaimInvestigationCollectionJobs(ctx, 1, 30*time.Second)
			if err != nil {
				errorsChannel <- err
				return
			}
			results <- jobs
		}()
	}
	claimedIDs := map[string]struct{}{}
	for range consumers {
		select {
		case err := <-errorsChannel:
			t.Fatalf("concurrent claim: %v", err)
		case jobs := <-results:
			if len(jobs) != 1 {
				t.Fatalf("concurrent claim returned %d jobs, want 1", len(jobs))
			}
			if _, exists := claimedIDs[jobs[0].ID]; exists {
				t.Fatalf("job %s was claimed more than once", jobs[0].ID)
			}
			claimedIDs[jobs[0].ID] = struct{}{}
		}
	}

	var retryable InvestigationCollectionJob
	for id := range claimedIDs {
		var investigationID string
		var attempt int
		var leaseToken string
		if err := db.QueryRowContext(ctx, `SELECT investigation_id::text, attempt_count, lease_token::text FROM investigation_collection_jobs WHERE id=$1`, id).Scan(&investigationID, &attempt, &leaseToken); err != nil {
			t.Fatalf("read job claim: %v", err)
		}
		if attempt == 1 {
			retryable = InvestigationCollectionJob{ID: id, InvestigationID: investigationID, AttemptCount: attempt, LeaseToken: leaseToken}
			break
		}
	}
	for attempt := 1; attempt < collectionJobMaxAttempts; attempt++ {
		if retryable.ID == "" {
			t.Fatal("could not find initial claim for retry exhaustion")
		}
		terminal, err := repository.RetryInvestigationCollectionJob(ctx, retryable.ID, retryable.LeaseToken, "source_unavailable", time.Microsecond)
		if err != nil || terminal {
			t.Fatalf("retry attempt %d terminal=%v err=%v, want retry", attempt, terminal, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE investigation_collection_jobs SET available_at=now()-interval '1 second' WHERE id=$1`, retryable.ID); err != nil {
			t.Fatalf("make retry available: %v", err)
		}
		jobs, err := repository.ClaimInvestigationCollectionJobs(ctx, 1, time.Second)
		if err != nil || len(jobs) != 1 || jobs[0].ID != retryable.ID || jobs[0].AttemptCount != attempt+1 {
			t.Fatalf("claim attempt %d jobs=%+v err=%v", attempt+1, jobs, err)
		}
		retryable = jobs[0]
	}
	terminal, err := repository.RetryInvestigationCollectionJob(ctx, retryable.ID, retryable.LeaseToken, "source_unavailable", 0)
	if err != nil || !terminal {
		t.Fatalf("exhaust retries terminal=%v err=%v, want terminal", terminal, err)
	}
	var status string
	var token *string
	if err := db.QueryRowContext(ctx, `SELECT status, lease_token::text FROM investigation_collection_jobs WHERE id=$1`, retryable.ID).Scan(&status, &token); err != nil {
		t.Fatalf("read exhausted job: %v", err)
	}
	if status != "FAILED" || token != nil {
		t.Fatalf("exhausted job status=%q lease_token=%v, want FAILED and no token", status, token)
	}

	crashed := fixtureAlertInput(fixture, "collection-concurrent-crashed")
	crashed.ProjectSlug = "collection-concurrent"
	created, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{crashed}, "collection-concurrent-crashed-request", filter)
	if err != nil {
		t.Fatalf("create investigation for crashed-worker lease: %v", err)
	}
	var crashedJobID string
	if err := db.QueryRowContext(ctx, `SELECT id::text FROM investigation_collection_jobs WHERE investigation_id=$1`, created[0].InvestigationID).Scan(&crashedJobID); err != nil {
		t.Fatalf("read crashed-worker job: %v", err)
	}
	for attempt := 1; attempt <= collectionJobMaxAttempts; attempt++ {
		jobs, err := repository.ClaimInvestigationCollectionJobs(ctx, 1, time.Second)
		if err != nil || len(jobs) != 1 || jobs[0].ID != crashedJobID || jobs[0].AttemptCount != attempt {
			t.Fatalf("claim crashed-worker attempt %d jobs=%+v err=%v", attempt, jobs, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE investigation_collection_jobs SET locked_until=now()-interval '1 second' WHERE id=$1`, crashedJobID); err != nil {
			t.Fatalf("expire crashed-worker attempt %d lease: %v", attempt, err)
		}
	}
	if jobs, err := repository.ClaimInvestigationCollectionJobs(ctx, 1, time.Second); err != nil || len(jobs) != 0 {
		t.Fatalf("claim after crash retry exhaustion jobs=%+v err=%v, want no jobs", jobs, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT status, lease_token::text FROM investigation_collection_jobs WHERE id=$1`, crashedJobID).Scan(&status, &token); err != nil {
		t.Fatalf("read crashed-worker exhausted job: %v", err)
	}
	if status != "FAILED" || token != nil {
		t.Fatalf("crashed-worker exhausted job status=%q lease_token=%v, want FAILED and no token", status, token)
	}
}
