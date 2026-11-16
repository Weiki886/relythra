# Issue #14 Prometheus Evidence persistence plan

## Goal

Persist one bounded Prometheus query result as immutable Investigation Evidence,
using the existing normalization and timeline contracts.

## Scope

- Add `Postgres.PersistPrometheusEvidence` to validate the Investigation and
  derive its service entity while holding a shared row lock.
- Normalize the connector result with the existing `evidence.FromPrometheusResult`
  adapter and persist it through `persistValidatedEvidence` in the same transaction.
- Cover valid writes, replay idempotency, timeline readback, missing or foreign
  Investigation, service mismatch, invalid context and empty-result semantics.
- Do not change the Prometheus connector, query templates, schema, or add
  scheduling/API orchestration.

## Files

- Add `internal/store/prometheus_evidence.go`.
- Add `internal/store/prometheus_evidence_integration_test.go`.
- Add this plan and its execution record.

## Validation

1. Write PostgreSQL integration tests for success/replay/readback and ownership
   rejection; confirm the new method is missing before implementation.
2. Implement one transaction that locks the Investigation, checks its service
   against any supplied service entity, derives canonical `SERVICE` identity,
   normalizes, inserts idempotently, and commits.
3. Run focused tests, race tests for store/evidence/API, `make check`, Gitleaks,
   and `git diff --check`. Report local checks separately from remote CI.

## Risk and rollback

Standard risk: bounded internal persistence using existing schema and writer;
no external calls, new permissions, migration, or API change. Rollback is a
revert of the isolated method, tests, and plan; persisted Evidence remains
immutable and does not require data cleanup.

## Execution record

- RED: the focused store tests failed to compile because
  `PersistPrometheusEvidence` did not exist.
- GREEN: `go test ./internal/store -run 'TestPersistPrometheusEvidence' -count=1`
  passed with PostgreSQL, including ownership, replay, missing-result and
  timeline assertions.
- `go test -race ./internal/store ./internal/evidence ./internal/api -count=1`
  passed.
- `RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null make check`
  passed, including Go vet/tests/build, frontend lint/typecheck/tests/build,
  diagnosis case validation, Compose rendering and local startup-script checks.
- `gitleaks dir --no-banner --redact` and `git diff --check` passed.
- No container smoke was run; remote CI will be reported from the PR checks.
