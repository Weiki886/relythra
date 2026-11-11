# Issue #14 Structured Collection Gaps

## Scope

Provide a safe normalization boundary for one connector query that failed before
it returned an observation. The result is a `MISSING` Evidence record with the
source template, affected entity, requested time window and a bounded reason
code. It can be persisted alongside successful connector evidence using the
atomic Evidence batch writer.

The API accepts no raw error, request URL, query text, response body or secret.
It does not classify errors, run connectors, persist records, or schedule work;
the caller maps connector errors to the stable reason-code enum and handles
collection orchestration. No schema or migration is required.

## Implementation and Verification

1. Add tests for explicit gap shape, missing completeness, source/template
   binding, stable semantic hash, invalid scope, reason-code rejection and
   fail-closed redaction requirements.
2. Implement `FromCollectionFailure` by delegating canonicalization, redaction
   and hashing to `evidence.Normalize`.
3. Run focused and race tests, `make check`, `gitleaks`, and `git diff --check`.

Rollback is a code revert. No stored records or runtime configuration change.

## Execution Record

- RED: `go test ./internal/evidence -run TestFromCollectionFailure -count=1`
  failed because the new API and its contract types did not exist.
- GREEN: focused collection-gap tests and
  `go test -race ./internal/evidence ./internal/store -count=1` passed.
- `make check` passed Go vet/tests/build, frontend lint/typecheck/tests/build,
  diagnosis-case validation and script checks. Compose config validation could
  not run because the installed Docker CLI does not support `docker compose`.
- `gitleaks detect --source . --no-git --redact` and `git diff --check` passed.
- The branch references Issue #14; this slice does not complete the pending
  connector orchestration and uses `Refs #14`.
