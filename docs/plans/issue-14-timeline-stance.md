# Issue #14 Timeline Stance Filter

## Scope and plan

Add an optional `stance` filter to the Investigation timeline API. `SUPPORTS`
and `CONTRADICTS` select evidence linked to at least one hypothesis in the
same Investigation. A record linked to multiple hypotheses appears once; this
filter does not identify which hypothesis or create any relations.

1. Extend API validation tests and PostgreSQL integration tests for combined
   filters, duplicate links, isolation, pagination, and invalid values. Run the
   tests before implementation to establish a failing baseline.
2. Update `internal/api/timeline_handler.go` and `internal/store/timeline.go`
   using the existing `hypothesis_evidence` table and a correlated `EXISTS`.
3. Document the API in README and run targeted tests, `make check`, and a
   changed-files secret scan. Report any integration environment limitations.

No migration or data writes are required. Rollback is a code and documentation
revert; existing relation data is unaffected. Issue #14 remains open.

## Verification

- API and store tests passed; the added API test initially failed to compile
  before the filter was implemented.
- Timeline integration tests passed against a dedicated temporary PostgreSQL
  instance, including multiple relations, isolation and pagination.
- `make check` passed; Go reported a non-fatal permission warning while writing
  its module metadata cache.
