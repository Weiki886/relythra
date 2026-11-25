-- +goose Up
CREATE TABLE investigation_collection_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id uuid NOT NULL UNIQUE REFERENCES investigations(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at timestamptz NOT NULL DEFAULT now(),
    locked_until timestamptz,
    last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'RUNNING') = (locked_until IS NOT NULL)),
    CHECK (status <> 'COMPLETED' OR last_error_code IS NULL)
);

CREATE INDEX investigation_collection_jobs_pending_idx
    ON investigation_collection_jobs (available_at, created_at)
    WHERE status IN ('PENDING', 'RUNNING');

CREATE TRIGGER investigation_collection_jobs_touch_updated_at
BEFORE UPDATE ON investigation_collection_jobs
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

COMMENT ON TABLE investigation_collection_jobs IS
    'Durable, idempotent request to collect registered read-only evidence for one Investigation.';

-- +goose Down
DROP TABLE IF EXISTS investigation_collection_jobs;
