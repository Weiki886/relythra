# Issue #14 — Preserve OOM window observations in runtime Evidence

## Scope and decisions

- Baseline: `bbf2823` (merged PR #60). Branch: `feat/14-oom-window-evidence`.
- Maintained behavior: carry the connector's positive five-minute OOM window observations into the existing OOM template's `value_summary.oom_window_observations`.
- Keep eight records and the original Prometheus independence group; this derivative is not a new event or independent vote. Preserve the raw measurement and its query evaluation time basis.
- A supplied observation must match its container, raw sample (including multiplicity), query interval, fixed five-minute window and source. Reject inconsistent input atomically. Empty/nil summaries remain accepted for older producers and do not manufacture observations from missing summaries.
- Observations identify the cgroup only, not a container incarnation. Their window can start before the request and container start; do not infer an OOM occurrence timestamp, sum overlapping estimates, or assign them to a boot instance.
- Omit the new JSON field when empty, preserving hashes for results without summaries. Preserve every supplied positive estimate without rounding. Canonicalize UTC and ordering on copies, then apply the existing redaction and size limits.
- No migration, new API endpoint, collector wiring, Agent, UI or real OOM injection in this slice. Existing generic Evidence persistence/timeline machinery carries the additive JSON field; an integration regression checks that path.

## Files and steps

1. Add `internal/evidence/runtime_oom_test.go`: first reproduce lost observations using the public adapter; cover raw preservation, grouping, cgroup identity, overlapping windows, replay ordering/timezones, redaction, invalid identities/times/estimates/sources, duplicate amplification and nil/empty compatibility.
2. Add `internal/evidence/runtime_oom.go` and update `internal/evidence/runtime.go`: validate supplied observations against a multiset of raw samples, canonicalize copies and include only in the OOM template summary.
3. Add `internal/store/runtime_oom_test.go`: normalize, batch persist, replay and read the timeline; assert the exact fractional estimate and window fields survive PostgreSQL JSONB.
4. Run focused red/green tests, race tests, repository Go/frontend/static checks and Gitleaks. PostgreSQL integration runs locally only with the dedicated test database configured, otherwise via CI. Record unavailable Compose explicitly.
5. Review the frozen diff against the baseline, exclude pre-existing `collector_test.go` and `.codebase-memory/`, commit, push and create a PR with `Refs #14` and `Refs #13` because full acceptance remains open. Verify final-head CI and leave human review pending.

## Risks and rollback

Standard scope: additive, bounded Evidence JSON; no schema/configuration/permissions change. Validation rejects inconsistent supplied derivatives instead of persisting unsupported claims. Existing stored records and empty-summary hashes remain unchanged. Populated summaries intentionally produce new content hashes. Revert this isolated commit to stop preserving the new field; existing JSONB records remain readable.

## Execution ledger

- Synchronized main and removed merged local PR #60 branch; remote branch was already deleted.
- Preserved pre-existing `internal/connector/runtime/collector_test.go` and untracked `.codebase-memory/`.
- TDD red: `go test ./internal/evidence -run 'TestFromRuntime.*OOM' -count=1` reproduced discarded summaries and accepted inconsistent derivatives before the implementation. Green: `go test ./internal/evidence -run TestFromRuntime -count=1` passed after implementation.
- Added cross-container replay and inclusive request-boundary coverage. The adapter preserves cgroup ownership and does not mutate connector inputs.
- Validation: `make fmt-check vet test build web-check case-check dev-script-check` passed; frontend Vitest ran 3 tests. The initial unconfigured database run skipped database integration as designed.
- Validation: `go test -race ./internal/evidence ./internal/connector/runtime ./internal/store` passed.
- Ruling: locally installed PostgreSQL 17 tools allow a dedicated temporary cluster instead of relying solely on remote CI. Ran `go test -race ./internal/store ./internal/evidence ./internal/connector/runtime -count=1 -v` with `RELYTHRA_TEST_DATABASE_URL` pointed at that private temporary cluster; all packages passed without skipped tests, including `TestRuntimeOOMWindowsSurvivePersistenceReplayAndTimeline`. The cluster was stopped and its temporary directory removed. No existing PostgreSQL instance or user database was used.
- `gitleaks dir . --no-banner --redact` passed; `git diff --check` passed. The pre-existing collector test SHA256 remains `c61d171455de739a02e45ef93326d444141d7d4ce69bc921fd55255dd44cdc09`.
- Local limitation: `make compose-config` failed because this Docker CLI rejects `docker compose --file` (`unknown flag: --file`). Local full `make check`/Compose smoke are not claimed as passing; the required remote Compose job remains a separate gate.
- Author review: checked both repository conventions and Issue #14 requirements against the bounded diff. No identified blocker in this slice; full Issue acceptance, Worker integration, real OOM injection and human peer review remain pending. Use `Refs`, not an automatic issue-closing keyword.
