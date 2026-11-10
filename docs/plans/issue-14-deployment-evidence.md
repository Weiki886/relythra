# Issue #14 Deployment Evidence Adapter

## Scope

Convert one stored deployment event into one immutable evidence record. Use the
existing normalizer and deployment independence group; no schema, API, worker,
or automatic persistence changes. The caller is responsible for verifying the
event belongs to the investigation. An unfinished deployment, missing reference,
unverified or conflicting source, or a future event is partial, not missing.
Do not infer freshness or a failure cause. Retain the event version and source
conflicts, including original source time metadata. Do not expose idempotency keys
or arbitrary deployment metadata in the evidence snapshot.

## Implementation and verification

1. Add contract tests in `internal/store/deployment_evidence_test.go` for
   identity, original time, incomplete events, stable replay, redaction, and
   invalid input. Run the tests before implementation and record the failure.
2. Implement `internal/store/deployment_evidence.go` using `evidence.Normalize`,
   preserving source fields and grouping by deployment ID. Run focused tests and
   race tests for store and evidence.
3. Run `make check`, inspect the diff and scan changed files for secrets. Create
   a PR referencing #14; human review and CI remain required.

Rollback is a revert of this isolated adapter and tests. No persisted data or
deployment configuration is modified by this change.

## Execution record

- The initial contract test failed before the adapter existed. A subsequent
  review test also reproduced nonterminal statuses incorrectly marked complete;
  these statuses now produce partial evidence even if a finish time is present.
- `go test -race ./internal/store ./internal/evidence -count=1` passed.
- `make check` passed with placeholder secret-file paths; Compose was only
  rendered. Live PostgreSQL integration and Docker smoke tests were not run.
- This adapter is not wired into collection, persistence, or the timeline API;
  Issue #14 remains open for the remaining end-to-end work.
