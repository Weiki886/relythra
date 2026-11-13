-- +goose Up
ALTER TABLE evidence DROP CONSTRAINT evidence_source_type_check;
ALTER TABLE evidence ADD CONSTRAINT evidence_source_type_check
    CHECK (source_type IN ('DEPLOYMENT', 'GRAFANA', 'GITHUB', 'PROMETHEUS', 'LOKI', 'RUNTIME', 'MAPPING', 'SYSTEM'));

-- +goose Down
-- Preserve immutable alert snapshots instead of deleting or relabeling history.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM evidence WHERE source_type = 'GRAFANA') THEN
        RAISE EXCEPTION 'evidence contains immutable GRAFANA rows; migration 000009 cannot be rolled back without a separate data-preservation decision';
    END IF;
END;
$$;
-- +goose StatementEnd

ALTER TABLE evidence DROP CONSTRAINT evidence_source_type_check;
ALTER TABLE evidence ADD CONSTRAINT evidence_source_type_check
    CHECK (source_type IN ('DEPLOYMENT', 'GITHUB', 'PROMETHEUS', 'LOKI', 'RUNTIME', 'MAPPING', 'SYSTEM'));
