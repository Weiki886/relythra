# Issue #14 Loki Evidence persistence plan

## Goal

Persist one bounded Loki query page as immutable Investigation Evidence and
make it available through the existing timeline read path.

## Scope

- Add `Postgres.PersistLokiEvidence` using `evidence.FromLokiResult` and the
  existing validated Evidence writer.
- Require a caller-provided `SERVICE` UUID and verify it matches the locked
  Investigation before normalizing or writing.
- Preserve replay idempotency, page-local completeness/freshness, and timeline
  readback without changing the connector, schema, or API.
- Reject invalid context before database access and reject foreign Investigation
  or service ownership without leaving Evidence rows.
- Do not add multi-page orchestration, query scheduling, or caller-supplied
  LogQL.

## Files

- Add `internal/store/loki_evidence.go`.
- Add `internal/store/loki_evidence_integration_test.go`.
- Add this plan and execution record.

## Verification plan

1. Add integration tests for successful write/replay/timeline readback,
   mismatched Investigation/service rejection, invalid context, and empty vs
   partial-page completeness. Confirm the new method is missing.
2. Implement ownership validation under a transaction with a shared lock,
   normalize using the canonical `SERVICE` entity, write via
   `persistValidatedEvidence`, and commit.
3. Run focused PostgreSQL tests, store/evidence/API race tests, `make check`,
   `gitleaks dir --no-banner --redact`, and `git diff --check`.
4. Review the diff against Issue #14 and repository rules; open a PR using
   `Refs #14`, M2, and existing feature/backend/data labels. Do not
   merge or close Issue #14.

## Risk and rollback

Standard risk: bounded, internal Evidence persistence reusing the existing
schema and writer. It adds no migration, external call, permission, or API
surface. Revert the method and its tests/plan; persisted rows remain valid and
immutable and need no cleanup.

## Execution record

- RED: focused tests failed to compile because `PersistLokiEvidence` did not
  exist.
- GREEN: `RELYTHRA_TEST_DATABASE_URL=... go test ./internal/store -run
  'TestPersistLokiEvidence' -count=1` passed against the local PostgreSQL
  database; the test helper created and removed an isolated schema.
- `RELYTHRA_TEST_DATABASE_URL=... go test -race ./internal/store
  ./internal/evidence ./internal/api -count=1` passed with PostgreSQL
  integration tests enabled.
- `RELYTHRA_TEST_DATABASE_URL=... RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null
  RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null make check` passed Go vet/tests/build,
  frontend lint/typecheck/tests (3)/build, diagnosis case validation, Compose
  config rendering, and local startup-script checks.
- Final review: only the planned method, integration tests and plan are staged;
  the transaction verifies canonical service ownership before normalization,
  and rejected writes leave the timeline empty.
- `git diff --cached --check` and `gitleaks dir --no-banner --redact` passed.
- No migration, API, connector, dependency or deployment changes. No local
  container smoke was run; remote CI remains to be checked on the PR head.
