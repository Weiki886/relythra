# Issue #14 Evidence Relations

## Scope

Add the store operation for appending a `SUPPORTS` or `CONTRADICTS` link between
one hypothesis and one evidence record in the same Investigation. The existing
schema already owns the relation and rejects updates/deletes, so this change
adds no migration or mutable relation workflow.

The operation validates UUIDs and the stance, verifies ownership in the insert
statement, and treats an exact replay as successful with `created=false`. It
does not create hypotheses, infer stance, or expose a new API route.

## Implementation and Verification

1. Add PostgreSQL tests for insertion, replay, opposite stance, timeline
   readback, invalid input and cross-Investigation rejection.
2. Implement the append-only store method against `hypothesis_evidence`.
3. Run focused database tests when `RELYTHRA_TEST_DATABASE_URL` is configured,
   the full check suite, secret scan and diff checks.

Rollback is a code revert; persisted relations are immutable and remain
readable by the existing timeline.

## Execution Record

- RED: focused tests failed to compile because `AddEvidenceRelation` was
  missing.
- GREEN: `RELYTHRA_TEST_DATABASE_URL='<local-test-dsn>' go test -race ./internal/store -run 'TestAddEvidenceRelation' -count=1`
  passed with PostgreSQL enabled. The test helper created a temporary schema,
  applied migrations, and dropped that schema during cleanup.
- `RELYTHRA_TEST_DATABASE_URL='<local-test-dsn>' RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null make check`
  passed Go vet/tests/build, web lint/typecheck/tests/build, diagnosis case
  validation, and stopped at Compose config validation because this host's
  Docker CLI does not support `docker compose --file`. No containers were
  started.
- `make dev-script-check`, `gitleaks detect --source . --no-git --redact`,
  `gofmt -d internal/store/evidence_relation.go internal/store/evidence_relation_test.go`,
  and `git diff --check` passed; Gitleaks reported no leaks.
- The PR references Issue #14; remaining collection orchestration and runtime
  identity acceptance are outside this slice.
