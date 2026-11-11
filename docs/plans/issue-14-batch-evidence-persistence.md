# Issue #14 Batch Evidence Persistence

**Goal**: Persist one Investigation's normalized Evidence records atomically and idempotently, retaining input order and per-record creation status.

**Architecture**: Add a PostgreSQL batch method capped at 100 records that validates the whole batch before opening a transaction, then reuses the single-record insert/replay behavior inside one transaction. Empty batches return empty results without database access; mixed-Investigation batches are rejected. This is a storage primitive only and does not claim to collect connector results or schedule Worker jobs.

**Requirements**: Issue #14's immutable/idempotent Evidence contract, `internal/evidence.Record`, and existing `Postgres.PersistEvidence` behavior.

## Constraints

- No network access, schema changes, API routes, Agent/Worker scheduling, or Docker startup.
- Do not mutate an existing Evidence row during replay.
- A batch must be wholly committed or wholly rolled back and contain no more than 100 records.
- Preserve the order of input records in both returned slices.

### Task 1: Add batch persistence contract

**Files**
- Modify: `internal/store/evidence_test.go`
- Modify: `internal/store/postgres.go`
- Add: `docs/plans/issue-14-batch-evidence-persistence.md`

**Interface**
- Consume: `[]evidence.Record` normalized for one Investigation.
- Produce: `PersistEvidenceBatch(context.Context, []evidence.Record) ([]Evidence, []bool, error)`; result index matches input index and the boolean indicates whether that row was inserted during this call.

**Behavior and verification**
1. Add a PostgreSQL-backed test for a two-record batch and an in-batch semantic duplicate; assert stable order, one inserted row for the duplicate key, and `created` values `[true, true, false]`.
2. Add PostgreSQL-backed tests rejecting mixed-Investigation batches and batches where a later record references a ToolCall owned by another Investigation; assert no earlier record was committed.
3. Add database-free tests proving empty and oversized batches return before database access.
4. Run `go test ./internal/store -run 'TestPersistEvidenceBatch' -count=1` and confirm it fails because the method is missing.
5. Implement empty/oversize handling, whole-batch validation, same-Investigation validation, transaction ownership, and single-record insert/replay through a shared private query helper.
6. Repeat the focused integration tests, then run `go test ./internal/store ./internal/evidence -count=1`, `make check`, and `git diff --check`.
7. Commit as `feat(store): persist evidence batches atomically` and open a PR using `Refs #14`.

## Verification

- RED: the focused test failed only because `PersistEvidenceBatch` did not exist.
- GREEN: focused PostgreSQL store tests passed, including atomic rollback and idempotent replay, using the local `relythra` database and temporary test schemas.
- With `RELYTHRA_TEST_DATABASE_URL` set to the local `relythra` test database, `go test ./cmd/... ./internal/... ./migrations/... -count=1` passed with PostgreSQL integration tests enabled.
- With the same test database setting, `go test -race ./internal/store ./internal/evidence -count=1` passed.
- `make check`: Go vet/tests/build, frontend lint/typecheck/tests/build, and evaluation-case validation passed. Compose config validation could not run because the installed Docker CLI does not recognize `docker compose`; no container was started.
- `git diff --check`: passed.

## Rollback

Revert the method, tests and this plan. There is no schema change or persisted data format change.
