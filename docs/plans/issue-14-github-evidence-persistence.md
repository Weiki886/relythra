# Issue #14 GitHub Evidence persistence entry

## Scope

Add a transaction-backed `Postgres.PersistGitHubEvidence` entry point for one
already-fetched `github.Result`. It validates that the referenced deployment is
a candidate for the supplied Investigation, that the candidate, incident,
service, project and environment agree, and that the connector Commit SHA equals
the canonical deployment Commit SHA. The service entity is derived from the
locked database row before calling `evidence.FromGitHubResult`; persistence
continues through the existing immutable, idempotent Evidence path.

No GitHub network request, API route, Worker scheduling, schema migration,
candidate creation, relation generation or arbitrary query support is included.
The caller remains responsible for obtaining a bounded connector result and
ToolCall ID. `Refs #14` is used because this slice does not finish the timeline
API or the rest of the Issue.

## Implementation plan

1. Add PostgreSQL integration coverage for successful timeline persistence,
   idempotent replay, a different Investigation, an unlinked deployment, and a
   connector Commit SHA that differs from the deployment fact. Confirm the new
   tests fail before implementing the store method.
2. Implement the method in `internal/store/github_evidence.go`. Hold shared row
   locks over Investigation, Incident, candidate and deployment during
   validation and Evidence insertion so ownership cannot change mid-write.
   Reject inconsistent ownership as `ErrNotFound`; reject a Commit SHA mismatch
   as `ErrConflict`.
3. Run the focused integration tests with the isolated PostgreSQL schema, Race
   tests, `make check`, Gitleaks and diff checks. Record unavailable Docker or
   remote CI checks separately.

## Risk and rollback

This slice has standard risk: it adds a bounded persistence path but no schema,
external side effect, API exposure or migration. Transaction failure leaves no
Evidence row. Roll back by reverting the isolated code, tests and plan; existing
Evidence and deployment facts remain untouched.
