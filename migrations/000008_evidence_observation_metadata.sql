-- +goose Up
ALTER TABLE evidence DROP CONSTRAINT evidence_completeness_check;
ALTER TABLE evidence ADD CONSTRAINT evidence_completeness_check
    CHECK (completeness IN ('COMPLETE', 'PARTIAL', 'MISSING', 'EXPIRED'));
ALTER TABLE evidence
    ADD COLUMN collected_at timestamptz,
    ADD COLUMN query_parameters jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(query_parameters) = 'object');

COMMENT ON COLUMN evidence.collected_at IS
    'Time the source observation was collected, separate from its observed event interval.';
COMMENT ON COLUMN evidence.query_parameters IS
    'Redacted, bounded parameter snapshot for reproducing the source query.';

-- +goose Down
-- Refuse to erase the EXPIRED distinction when downgrading to the older contract.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM evidence WHERE completeness = 'EXPIRED') THEN
        RAISE EXCEPTION 'evidence contains immutable EXPIRED rows; migration 000008 cannot be rolled back without a separate data-preservation decision';
    END IF;
END;
$$;
-- +goose StatementEnd

ALTER TABLE evidence DROP CONSTRAINT evidence_completeness_check;
ALTER TABLE evidence ADD CONSTRAINT evidence_completeness_check
    CHECK (completeness IN ('COMPLETE', 'PARTIAL', 'MISSING'));
ALTER TABLE evidence DROP COLUMN query_parameters, DROP COLUMN collected_at;
