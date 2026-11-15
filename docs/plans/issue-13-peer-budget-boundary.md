# Issue #13: Keep peer references within the returned runtime budget

## Scope

When runtime container results exceed `MaxSeries`, truncate the result and remove peer IDs for containers omitted by that same limit. Add `runtime_peer_links_truncated` alongside `runtime_entities_truncated` so callers know the returned peer set is incomplete. Peer IDs remain comparison candidates and do not assert health.

## Verification

- A regression test supplies three explicitly mapped containers with a two-container result budget.
- The test requires every peer ID to reference a returned container, excludes self references, and checks both truncation gaps.
- Run the runtime connector tests and the repository's local checks; report Docker-backed verification separately if the selected Docker context is unavailable.

## Execution record

- Red: `go test ./internal/connector/runtime -run '^TestQueryTruncatesPeerReferencesWithContainerBudget$' -count=1` failed because returned instances referenced the omitted third peer.
- Green: the same focused test passed after pruning references and adding the peer-link gap.
- `go test -race ./internal/connector/runtime ./internal/evidence -count=1` passed.
- `RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null make check` passed. `/dev/null` was used only for Compose config rendering; no Compose services were started by this command.
- `gitleaks detect --source . --no-git --redact` and `git diff --check` passed.
- `make demo-smoke` could not complete: Kiri's VM stopped and its daemon reported `the guest kernel guest/out/Image is missing: reinstall Kiri`. The Docker-backed demonstration remains unverified in this environment.

## Risk and rollback

Risk is high because incomplete peer references can invalidate or distort runtime Evidence. The change only bounds existing references, marks incompleteness, and is reverted with this isolated PR. It adds no schema, migration, dependency, or external side effect.
