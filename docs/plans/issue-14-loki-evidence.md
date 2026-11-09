# Issue #14 Loki Evidence Adapter

## Scope and contract

Convert one successful Loki query page into one immutable Evidence record using the existing `Normalize` boundary. No network calls, persistence, migrations, query scheduling or API changes are introduced. This independently reviewable slice uses `Refs #14`; the overall issue remains open.

- `LokiEvidenceContext` supplies Investigation/ToolCall IDs, exact entity mapping and collection time. An absent entity ID remains absent.
- `FromLokiResult(ctx context.Context, result loki.Result, observation LokiEvidenceContext, filter *redact.Filter) (Record, error)` preserves query bounds in UTC, query/source reference, template/version/direction/severity/limit and response digest.
- The summary preserves every entry, including original nanosecond timestamp, labels, `untrusted_data` log text, truncation and window flags, warnings and source status flags. Nil entries/warnings become empty arrays. Preserve page order; the connector already sorts deterministically.
- `PARTIAL` takes priority over `MISSING`: upstream partial/warnings, another page, skew, out-of-window/future entries or clipped lines mean incomplete evidence, even if this page is empty. A clean empty page is `MISSING`; only a nonempty, fully observed page is `COMPLETE`. Do not infer `EXPIRED` from log age.
- `has_more` records pagination without storing the opaque continuation token. Page content participates in the hash; all pages for a template share `loki:<template>:v<version>` as a conservative independence group.
- Freshness is the age in whole seconds of the latest entry on this page, only when all timestamps are nonzero, no skew/window warning is present, and the latest timestamp is not after collection. This is page-local recency, not a health or expiry judgment. Unknown or suspect timestamps leave freshness null.
- Require explicit `trust=untrusted_data` and `source=loki` on every log. Reject malformed trust metadata and zero timestamps; never promote untrusted text into instructions. Run all snapshots through the existing fail-closed redactor before hashing.
- Existing 64 KiB per JSON-object/text limits remain authoritative. Oversized pages return `ErrInvalidInput` without silently dropping entries. A future collector must reduce its requested page size or record a collection gap; this adapter does not silently split or discard logs.

## Implementation and red/green verification

Files: `internal/evidence/loki.go`, `internal/evidence/loki_test.go`, this plan.

1. Write tests for canonical metadata, nanosecond source timestamps, untrusted text, completeness precedence, freshness, entity gaps, redaction, replay/page hashes, invalid contracts, nil filter, canceled context, and oversized snapshots. Run `go test ./internal/evidence -run TestFromLoki -count=1`; confirm missing adapter symbols fail compilation.
2. Define `LokiEvidenceContext` with string fields `InvestigationID`, `ToolCallID`, `EntityType`, `EntityID` and `CollectedAt time.Time`. Marshal bounded query and summary objects, compute status/recency and call `Normalize` with `SourceLoki` and source timezone UTC. No shared-layer changes or new dependencies are needed.
3. Repeat focused tests, then `go test -race ./internal/evidence ./internal/connector/loki -count=1`, repository `make check`, `git diff --check` and staged gitleaks scan. PostgreSQL tests require a dedicated test URL; absence must be reported explicitly.
4. Review the frozen diff against #14 and AGENTS.md; submit an English-title/Chinese-body PR with M2 and existing feature/backend/data/connector labels. Do not close #14 or merge the PR.

## Risk and rollback

Standard risk: internal adapter only, sensitive log content crosses the existing redaction boundary. No schema, external write, running-process or frontend behavior changes. Revert this commit to roll back; existing evidence contracts remain compatible.

## Execution ledger

- Plan reviewed against the existing Loki result and Evidence contracts. Sequential implementation in this session.

- Red: the initial `go test ./internal/evidence -run TestFromLoki -count=1` failed because `LokiEvidenceContext` and `FromLokiResult` did not exist. The first implementation also exposed the missing source-reference validation; it was added before passing the contract suite.
- Red/green regression: `TestFromLokiCompletenessAndFreshness/future` first reported `COMPLETE` instead of `PARTIAL`; marking future observations partial made it pass without changing the expected behavior.
- Final implementation verification: `go test -race ./internal/evidence ./internal/connector/loki -count=1` passed for both packages. `RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null make check` passed Go format/vet/tests/build, frontend lint/typecheck/tests (3)/build, the diagnosis fixture check (1 case), and Compose config rendering. The `/dev/null` paths only satisfy Compose interpolation for configuration rendering; no service was started.
- Local PostgreSQL integration tests were skipped because no dedicated test URL was configured. They remain subject to the Backend CI job with its isolated PostgreSQL service; the local suite is not evidence of PostgreSQL execution.
- Diff review: base `a8e6702` (`origin/main`) plus exactly the three files listed above. Axis A checks trust/redaction, immutable input, UTC/nanoseconds, pagination bounds, completeness precedence and semantic hashing. Axis B is the Loki adapter slice of #14, not completion of the whole issue. No blocking finding remains in this author review; human review is still required.
- Scope ruling: use `Refs #14` instead of the repository's default `Closes` wording because this PR does not satisfy the remaining cross-source orchestration and timeline acceptance criteria. No migration, dependency, API or deployment change. Revert this change to roll back.
