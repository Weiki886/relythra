# Issue #14 Evidence Timeline Implementation Plan

## Current PR Scope

Deliver the first usable read path for Investigation evidence: a bounded, filterable API backed by the existing immutable `evidence` records. Preserve report snapshots and the current single-evidence endpoint.

The response will return persisted Evidence records in deterministic UTC event-time order, with pagination metadata. Supported filters for this increment are source type, entity ID, and completeness. Investigation IDs and all filter values are validated before database access. The query uses a read-only repeatable-read transaction so the total and page represent one snapshot.

## Existing Contract Reused

Migration `000002_domain_model.sql` already stores source/entity identity, observed start/end, query text, raw reference, summary, completeness, freshness, independence group, content hash, and original source timezone/time text. It also enforces Evidence immutability and per-Investigation content-hash idempotency. This PR does not duplicate those columns or alter historical records.

## Explicitly Deferred

- Converting Prometheus, Loki, GitHub, deployment, and runtime connector outputs into persisted Evidence. No production Evidence writer or orchestration path currently exists.
- Query-parameter snapshots, explicit expired status, structured collection-gap records, Evidence-to-Evidence support/refute relations, and their filters. The current schema has no storage contract for these; they must be designed with ingestion rather than inferred at read time.
- Agent, report-generation, and frontend integration.

These gaps remain visible in Issue #14; this PR must use `Refs #14`, not close it.

## Files and Verification

- `internal/store/timeline.go`: validated filter/page input and consistent read-only timeline query.
- `internal/store/postgres_test.go`: PostgreSQL integration coverage for filter combinations, deterministic ordering, count/page consistency, invalid inputs, and empty results.
- `internal/api/handler.go`: GET route, strict query validation, stable envelope, and pagination metadata.
- `internal/api/handler_test.go`: route, filter validation, method, and error mapping coverage with a fake reader.
- `README.md`: document the read endpoint and its current persisted-evidence boundary.

Run focused Go tests, `make check`, and the PostgreSQL-backed store/migration tests when `RELYTHRA_TEST_DATABASE_URL` is available. No new migration is planned. Rollback is a normal revert of the API/store/documentation changes; no data rewrite is required.
