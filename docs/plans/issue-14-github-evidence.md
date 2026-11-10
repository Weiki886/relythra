# Issue #14 GitHub Evidence Adapter

## Scope and contract

Convert one successful `github.Result` to one immutable Evidence through `Normalize`; no network, persistence, schema, API or Worker scheduling changes. This is a maintained, standard-risk slice of M2 and uses `Refs #14` because orchestration, runtime/deployment adapters and relations remain outstanding.

- Add `GitHubEvidenceContext` (Investigation/ToolCall IDs, exact entity mapping, collection time) and `FromGitHubResult`. Missing entity/ToolCall IDs remain absent.
- Require a full 40-hex commit SHA, valid DeploymentEvent UUID, nonzero author time and nonblank source reference. The connector owns deployment verification; the adapter preserves its association and does not independently prove the deployment belongs to the Investigation. The future collector must verify that association.
- Preserve commit author time as a point observation in UTC, explicitly identified as `commit_author_time`; never substitute it for deployment time. The connector already converts author time to UTC and does not retain its original timezone. Source time text/timezone therefore describe the connector's UTC representation. Freshness stays null: commit age does not express acquisition freshness, and no expiry policy exists.
- Snapshot commit SHA, DeploymentEvent ID and commit/diff response hashes. Preserve message, files/patches, omitted files, PRs/merge dates/references, dependency contents/references, diff, warnings and source flags. Exclude transport duration and ETags (including dependency ETags) from semantic data. Canonicalize nil arrays to empty arrays and PR merge times to UTC without mutating input.
- One record for the commit and all its derived fragments, with independence group `deployment:<DeploymentEventID>`, to avoid counting PRs/diffs/dependencies as independent evidence of that deployment.
- Mark PARTIAL for upstream partial/truncated flags, warnings, omissions, missing PR/diff, PR pagination truncation, any clipped untrusted text, or future author time. Preserve successful fragments and gap flags; never turn a known commit with missing subresources into MISSING or infer EXPIRED.
- Validate `trust=untrusted_data` and `source=github` on every message/title/patch/diff/dependency content. Reuse fail-closed redaction and existing 64 KiB Evidence JSON bounds; reject oversized results without dropping evidence. The caller must request smaller connector limits or record a collection gap.

## Plan, verification and rollback

Files: `internal/evidence/github.go`, `internal/evidence/github_test.go`, this plan. No new abstraction/dependency: existing connector types, standard JSON/hex/time and `Normalize` cover the requirement.

1. Write contract tests for associations, timestamps and source semantics, full snapshots, all partial signals, immutable input, redaction/trust, semantic replay, malformed input, nil context/filter, cancellation and size limits. Run `go test ./internal/evidence -run TestFromGitHub -count=1` and observe missing symbols before implementation.
2. Implement bounded snapshots and trust/completeness validation; run focused tests and race tests for Evidence/GitHub connector.
3. Run repository `make check`, diff whitespace and gitleaks scan. Report PostgreSQL or Docker tests that could not execute separately from executed checks.
4. Freeze/review the diff under code-review, commit and push; create an English-title/Chinese-body PR with Issue #14's milestone and labels. Human review remains required; do not merge.

Rollback: revert this isolated change. No migration, configuration, external write or runtime wiring changes.

## Execution ledger

- Baseline: `eff00df` (merged PR #49), fetched latest `origin/main`; only pre-existing untracked `.codebase-memory/` cache excluded. Remote/local branches already contain only main.
- Scope ruling: use `Refs #14` instead of the repository's default `Closes` wording because this adapter does not complete the whole Issue.
- Red: before implementation, `go test ./internal/evidence -run TestFromGitHub -count=1` failed with undefined `GitHubEvidenceContext`/`FromGitHubResult`; the same command passed after implementation.
- Green: `go test -race ./internal/evidence ./internal/connector/github -count=1` passed. `RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null make check` exited 0 (Go format/vet/tests/build, frontend lint/typecheck/tests/build, case validation and static Compose config). `/dev/null` supplies static interpolation only.
- Security: `gitleaks dir internal/evidence --no-banner --redact` reported no leaks. No real credentials or source data were added.
- Review: scope is baseline `eff00df` plus the three explicitly staged files. Axis A checked validation, fail-closed redaction, bounded serialization, untrusted text, input immutability and semantic hash stability; no blocking finding. Axis B checked the GitHub adapter slice against #14; full Investigation orchestration, runtime/deployment adapters and relations are outside this slice. This is author review, not independent or human approval.
- Verification limits: local PostgreSQL integration tests were not enabled with `RELYTHRA_TEST_DATABASE_URL`; runtime Docker smoke/demo-smoke were not run locally. Remote Backend/PostgreSQL, Frontend and Compose smoke results must be checked on the submitted commit. Human review remains required.
