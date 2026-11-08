# Issue #14 Evidence Normalization and Persistence Plan

## Current PR Scope

Add a reusable normalization boundary and append-only, idempotent PostgreSQL writer for one normalized Evidence observation. Persist UTC event bounds, source time text/timezone, collection time, safe query text and parameter snapshot, source reference, summary, completeness, freshness and independence group.

Evidence content hashes cover the canonical, redacted semantic observation. They exclude collection time and tool-call ID so replaying the same observation does not create a duplicate. The writer relies on the existing `(investigation_id, source_type, content_hash)` uniqueness contract and cross-Investigation ToolCall foreign key.

`MISSING` records represent structured collection gaps without inventing zero-valued measurements. `EXPIRED` means the caller has determined an observation is outside its validity policy; the normalizer does not infer expiry from wall-clock time.

## Implementation Status

- Added `internal/evidence.Normalize` and `Validate` for bounded JSON objects, fail-closed text/JSON redaction, UTC event/collection timestamps, completeness validation, and deterministic SHA-256 hashes. `MISSING` may omit query text and raw reference when the source returned no observation.
- Added migration `000008` with nullable `collected_at` (historical collection time remains unknown rather than being inferred), a JSON-object `query_parameters` snapshot, and `EXPIRED` support. Downgrade refuses to erase existing `EXPIRED` states.
- Added `Postgres.PersistEvidence`, which validates normalized records, appends once using the existing uniqueness key, and returns the immutable first row for semantic replays.
- Extended Evidence readback and timeline filtering for collection metadata and `EXPIRED`.
- PostgreSQL-backed tests cover migration up/down, metadata round-trip, replay idempotency, `EXPIRED` filtering, and cross-Investigation ToolCall rejection.

## Explicitly Deferred

- Per-connector adapters and orchestration that produce Evidence from Prometheus, Loki, GitHub, DeploymentEvent, and Runtime result types.
- Evidence-to-Evidence support/refute relations and relation filters.
- Investigation-level data-gap aggregation, Agent/Worker scheduling, and frontend workbench integration.

This is a foundation slice; Issue #14 remains open and the PR uses `Refs #14`.

## Files and Verification

- `internal/evidence`: validated, redacted, UTC-normalized canonical observation and deterministic hash.
- `internal/store/postgres.go` and `internal/store/timeline.go`: persisted fields, immutable idempotent insert, replay result, and `EXPIRED` timeline filtering.
- `migrations/000008_evidence_observation_metadata.sql`: collection timestamp, query parameter snapshot and EXPIRED enum support with reversible schema changes.
- Tests: normalization/hash/redaction/validation unit tests; PostgreSQL migration, dedupe, immutability and foreign-key integration tests.

Verification completed: `make check` (PostgreSQL URL supplied; Compose secret file paths set to `/dev/null` for static config validation), `RELYTHRA_TEST_DATABASE_URL=... go test -race ./internal/... ./migrations/... -count=1`, and targeted gitleaks scans for changed test and migration files pass. A whole-history `gitleaks git` scan also reports three pre-existing test Canary findings in commit `006762f`; none are in this change.

Rollback is a code revert plus a forward-compatible schema. The migration down path removes only new metadata columns and restores the prior completeness constraint, but refuses to run while immutable `EXPIRED` rows exist; it is not part of routine rollback. Preserve data and use forward repair if the application version must be reverted after new evidence has been written.
