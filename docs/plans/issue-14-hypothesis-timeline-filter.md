# Issue #14 hypothesis timeline filter

## Scope

Add an optional `hypothesis_id` filter to the Investigation timeline API and
PostgreSQL reader. It selects Evidence linked to that hypothesis within the
requested Investigation; existing relation payloads remain complete for every
returned item. The filter composes with source, entity, completeness, stance and
pagination.

No schema, write path, hypothesis generation, cross-Investigation lookup or
relation mutation is included. This is a standard-risk read-only API extension
and uses `Refs #14` because the Issue remains incomplete.

## Plan and verification

1. Extend store and API tests to prove only Evidence linked to the requested
hypothesis is returned, a foreign Investigation hypothesis returns no rows,
invalid IDs are rejected before database access, and pagination totals reflect
the filtered set. Observe failure before implementation.
2. Validate UUID syntax and add a parameterized, Investigation-scoped `EXISTS`
   predicate to the existing timeline query. Parse the new query key through
   the existing strict URL validation path.
3. Run targeted PostgreSQL and API tests, Race tests, `make check`, Gitleaks and
   diff checks. Record remote CI separately.

## Risk and rollback

No migration or write behavior. Existing callers remain compatible because the
filter is optional. Rollback is a revert of the code, tests and plan; no data
cleanup is needed.

## Execution record

- Red: the focused API/store tests initially failed to compile because the
  `HypothesisID` filter field did not exist.
- Green: the focused PostgreSQL and API tests passed after implementation.
- `go test -race ./internal/store ./internal/api -count=1` passed with the local
  isolated-schema PostgreSQL test setup.
- `make check` passed, including Compose configuration validation; container
  smoke was not run locally.
- `gitleaks dir --no-banner --redact` and `git diff --check` passed.
