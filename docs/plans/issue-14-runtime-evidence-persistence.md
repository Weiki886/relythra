# Issue #14 Runtime Evidence persistence plan

## Goal

Persist all normalized observations from one bounded runtime result atomically
and associate them only with the Investigation's canonical service.

## Scope

- Add `Postgres.PersistRuntimeEvidence` around the existing eight-record runtime
  adapter and the existing immutable Evidence writer.
- Require a caller-validated service UUID and compare it with the Investigation
  under a shared row lock held through the batch commit.
- Preserve all-or-nothing writes, semantic replay idempotency, adapter completeness
  states, and existing timeline readback.
- Reject invalid context before database access, foreign Investigation/service
  association, and ToolCalls owned by another Investigation without partial rows.
- Do not change the runtime connector, adapter semantics, schema, API or Worker
  scheduling.

## Files

- Add `internal/store/runtime_evidence.go`.
- Add `internal/store/runtime_evidence_integration_test.go`.
- Add this plan and execution record.

## Verification plan

1. Add PostgreSQL integration tests for write/replay/timeline readback,
   ownership rejection, invalid context, and atomic rollback on a foreign
   ToolCall. Confirm the new method is missing.
2. Validate the Investigation/service context, normalize the complete runtime
   result, persist every record using the existing validated writer in one
   transaction, and commit only after all records succeed.
3. Run focused PostgreSQL tests, store/evidence/API race tests, `make check`,
   `gitleaks dir --no-banner --redact`, and `git diff --check`.
4. Review and open a PR with `Refs #14`, M2, and labels matching this scoped
   change. Do not merge or close Issue #14.

## Risk and rollback

Standard risk: bounded internal persistence of already-normalized runtime
observations using the existing schema. It adds no migration, external call,
permission, API route or deployment change. Revert the method and its tests/plan;
persisted immutable evidence remains valid and requires no cleanup.

## Execution record

- RED: `go test ./internal/store -run '^TestPersistRuntimeEvidence' -count=1`
  failed to compile because the persistence context and method were missing.
- GREEN: `RELYTHRA_TEST_DATABASE_URL=<isolated-local-postgres-url> go test
  ./internal/store -run '^TestPersistRuntimeEvidence' -count=1 -v` passed against
  PostgreSQL, exercising batch persistence, replay, ownership and rollback.
- `RELYTHRA_TEST_DATABASE_URL=<isolated-local-postgres-url> go test -race
  ./internal/store ./internal/evidence ./internal/api -count=1` passed.
- `RELYTHRA_TEST_DATABASE_URL=<isolated-local-postgres-url>
  RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null
  RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null make check` passed, including Go,
  frontend, case validation, Compose rendering and local startup script checks.
  The PostgreSQL tests use isolated temporary schemas; placeholder secret paths
  were used only for Compose configuration rendering.
- `gitleaks dir --no-banner --redact` and `git diff --check` passed.
