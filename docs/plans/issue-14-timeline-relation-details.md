# Issue #14 Timeline Relation Details

## Scope

Expose the support/refute hypothesis links already persisted for each
Investigation timeline evidence item. Each relation includes the hypothesis ID
and `SUPPORTS`/`CONTRADICTS` stance. A stance filter controls which evidence
items are included; returned items retain all of their current relations so
opposing evidence remains visible. Evidence without relations returns an empty
array. This does not rank hypotheses or declare a root cause.

## Implementation

1. Add a PostgreSQL integration test asserting complete relation metadata,
   unlinked evidence behavior, and investigation isolation.
2. Add a timeline-specific response type and load relation rows for only the
   paginated evidence IDs within the existing read-only repeatable-read
   transaction.
3. Update API documentation and rerun the focused tests and repository checks.

No migration is needed. Revert the isolated commit to roll back the response
extension.

## Verification

- API and PostgreSQL store tests pass with the relation assertions enabled.
- `make check` passes against a dedicated PostgreSQL 17 test instance.
- PostgreSQL 18 was also tried; an unrelated existing migration test expects
  SQLSTATE `23503` but PostgreSQL 18 reports `23001` for its `RESTRICT` case.
- No Docker service was started; Compose validation only rendered config.
