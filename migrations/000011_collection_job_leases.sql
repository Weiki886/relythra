-- +goose Up
ALTER TABLE investigation_collection_jobs
    ADD COLUMN lease_token uuid;

ALTER TABLE investigation_collection_jobs
    ADD CONSTRAINT investigation_collection_jobs_lease_token_check
    CHECK ((status = 'RUNNING') = (lease_token IS NOT NULL));

CREATE INDEX investigation_collection_jobs_expired_lease_idx
    ON investigation_collection_jobs (locked_until, created_at)
    WHERE status = 'RUNNING';

COMMENT ON COLUMN investigation_collection_jobs.lease_token IS
    'Opaque claim token required for a Worker to complete or reschedule its active lease.';

-- +goose Down
DROP INDEX IF EXISTS investigation_collection_jobs_expired_lease_idx;
ALTER TABLE investigation_collection_jobs DROP CONSTRAINT investigation_collection_jobs_lease_token_check;
ALTER TABLE investigation_collection_jobs DROP COLUMN lease_token;
