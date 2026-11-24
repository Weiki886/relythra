# Issue #14 Runtime Collection Gap Evidence

**Goal**: Preserve failed Docker Compose runtime query templates as structured `MISSING` Evidence while keeping successful runtime observations.

**Architecture**: The Runtime Collector records only the registered source, template ID, and a bounded reason code when an individual Prometheus or Loki query fails. `FromRuntimeResult` converts these records through `FromCollectionFailure`, using the same Investigation, host scope, query window, collection time, and redaction filter as the successful runtime Evidence.

**Requirements**: Issue #14 requires partial collection to retain successful evidence and represent failed sources as structured gaps. Existing `FromCollectionFailure` already defines the safe Evidence boundary; this plan connects it to runtime collection results.

## Constraints

- Runtime collection remains read-only and restricted to registered templates.
- Never include raw errors, URLs, queries, response bodies, or secrets in failure records.
- Cancellation aborts the whole collection and is not recorded as a source failure.
- A failed template must not discard successful template results.
- No database migration, public endpoint, scheduler, or external write is added.

## Task 1: Capture bounded per-template failures

**Files**
- Modify `internal/connector/runtime/collector.go`.
- Test `internal/connector/runtime/collector_test.go`.

**Behavior**
- Add a `CollectionFailure` result field with source type, registered template ID, and reason code.
- Map Prometheus/Loki connector error categories to `timeout`, `rate_limited`, `permission_denied`, `unavailable`, `invalid_response`, `request_rejected`, or `unknown`.
- Keep existing coarse `Gaps` and `Partial` behavior for compatibility.

**Tests**
- One Prometheus template failure and one Loki failure retain successful metric/log results and include only the expected safe failure metadata.
- Unknown errors map to `unknown`; caller cancellation still returns an error and no partial result.

## Task 2: Normalize failed templates as MISSING Evidence

**Files**
- Modify `internal/evidence/runtime.go`.
- Test `internal/evidence/runtime_test.go`.

**Behavior**
- Convert each collector failure through `FromCollectionFailure`.
- Bind each gap to the same Investigation, tool call, host, observed window, collection time, and registered source template.
- Return successful template Evidence and missing Evidence in deterministic template order.
- Reject duplicate or invalid failures as `ErrInvalidInput`; never serialize free-form error content.

**Tests**
- Verify a failed template yields `MISSING` Evidence while a successful template remains represented.
- Verify source/template/entity/window/reason metadata and stable replay hash.
- Verify invalid and duplicate failures fail closed without partial record output.

## Verification and rollback

- Run the focused Runtime Collector and Evidence tests, then race tests for both packages.
- Run `make check`, Gitleaks, and `git diff --check`.
- Roll back by reverting this PR; no persisted data or runtime configuration changes.
- This is a partial Issue #14 delivery and must use `Refs #14`.

## Execution record

- RED: the new Runtime Collector tests failed to compile because the result had no structured failure contract; after the contract was added, the Evidence tests failed because failed templates still normalized as `RUNTIME/PARTIAL` and invalid/duplicate failures were ignored.
- GREEN: `go test ./internal/connector/runtime ./internal/evidence -count=1` passed.
- `go test -race ./internal/connector/runtime ./internal/evidence -count=1` passed.
- `RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null make check` passed, including Go checks, frontend checks/build, case validation, Compose config rendering, and dev script checks. The Compose service smoke environment was not started.
- `gitleaks detect --source . --no-git --redact` and `git diff --check` passed.
