# Issue #14 Runtime Evidence Adapter

## Scope and choices

Maintained, standard-risk slice of M2. Convert `runtime.Result` into immutable Evidence via the existing `Normalize`, using connector types and the standard library. No new dependency, network access, schema, persistence, API or Worker wiring. Use `Refs #14`; deployment adaptation, orchestration, relations and aggregate gaps remain outstanding.

A runtime result combines seven Prometheus templates and one Loki template. A single snapshot with a new independence group would incorrectly make these derived observations independent of their originals. Instead, `FromRuntimeResult` returns eight records in fixed template order (host CPU/memory/load, container CPU/memory/OOM/start, lifecycle logs), reusing the existing `prometheus:<template>:v1` and `loki:<template>:v1` groups. One record contains all entities for that query. All are `RUNTIME` observations associated with the requested host; request service/environment are scope, not a verified container-to-service mapping.

- Context supplies Investigation/ToolCall IDs and collection time. The adapter accepts only Docker Compose and a nonblank host/service/environment, a positive window <= 2h and nonnegative transport duration.
- Query parameters preserve runtime, request scope, template/version, underlying source and time basis. The result does not retain the raw query, step, query budget or response hash; do not invent them. `query_text` stays empty. A record's reference comes from its measurements/events; inconsistent references in the same query are rejected. An unavailable/empty query may have no reference, explicitly recorded as unavailable.
- Metric summaries preserve every returned measurement, its delay (nanoseconds), flags and reference, and exact host/container identity metadata. Container start time is preserved only in the start query. Derived `state`, `last_observed_at`, `stale`, `clock_skew` and peer lists are not reified as extra evidence: samples/measurement flags retain their primary observations, and existing mapping/peer/freshness gaps retain the limitations. No host health or verified restart/OOM/death classification is inferred.
- Lifecycle events retain the unverified classification, empty container association, source reference, outside-window flag and untrusted Loki text. Reject other trust/source/classification or asserted container association; the current collector cannot verify those.
- Every summary retains the result's gaps and partial flag. Canonicalize arrays, gap order, entity order, sample order and nested timestamps to UTC on copies. Exclude transport duration and collection/ToolCall identity from semantic data. Same observations in equivalent timezones/order remain idempotent; changed samples/logs/gaps change the hash.
- PARTIAL takes precedence for upstream partial/gaps, incomplete/empty/stale measurements, out-of-window/future samples, clipped/out-of-window logs, or unverified lifecycle matches. Without partial signals and without samples/events use MISSING; otherwise COMPLETE. `freshness_seconds` stays null: evaluation timestamps do not establish exporter scrape age. Do not infer EXPIRED or runtime health. An all-failed snapshot still returns eight explicit gap records without fabricated zero samples.
- Reject mismatched host identity, invalid/nonfinite samples, negative delay, contradictory Empty flags, invalid times and source-less observations. Preserve empty measurements without a reference. Reuse fail-closed redaction, cancellation and 64 KiB per-record bounds. On any error return no records; callers must not insert partial adapter output.

## Files, verification and rollback

Files: `internal/evidence/runtime.go`, `internal/evidence/runtime_test.go`, this plan.

1. Add contract tests derived from Issue #14 and collector semantics: query grouping/source references, primary observations, gaps/missing, flags, nil arrays, UTC/replay, immutable input, redaction/untrusted lines, malformed input, cancellation/filter and bounded output. Run `go test ./internal/evidence -run TestFromRuntime -count=1` before implementation.
2. Implement the pure adapter; run focused tests and `go test -race ./internal/evidence ./internal/connector/runtime -count=1`.
3. Run repository `make check`, whitespace checks and gitleaks; distinguish local static checks from database/Docker execution.
4. Review frozen diff under code-review, commit/push and create a Chinese-body/English-title PR with #14's milestone/labels. Verify required CI on final head; human review remains required.

Rollback: revert the isolated commit. No migration, configuration or runtime wiring impact.

## Execution ledger

- Baseline `229422d` (merged PR #50). Latest origin/main was synchronized and merged local feature branch deleted. Pre-existing `.codebase-memory/` stays untracked.
- Scope decision: decomposition by underlying query rather than composite runtime grouping avoids claiming a new independent source with the scalar Evidence grouping contract. Query identity is known, but lost transport/query fields cannot be reconstructed as original provenance.
- Red: `go test ./internal/evidence -run TestFromRuntime -count=1` failed before implementation with undefined adapter symbols.
- Green: focused runtime adapter tests passed, including source grouping, gaps, replay, redaction, atomic errors and mixed missing observations. `go test -race ./internal/evidence ./internal/connector/runtime -count=1` passed.
- `RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null make check` passed; Compose was only rendered, not started. PostgreSQL integration and local Docker smoke were not exercised by this command.
- `gitleaks dir internal/evidence --no-banner --redact` found no leaks. Independent review was requested but did not return a result; human PR review remains required.
