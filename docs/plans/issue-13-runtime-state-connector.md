# Issue #13 Runtime State Connector Implementation Plan

**Goal**: Collect bounded Docker Compose host/container resource and lifecycle evidence through registered Prometheus and Loki templates while preserving instance identity, source timestamps, missing-data gaps, and the read-only boundary.

**Architecture**: Add fixed Prometheus templates for raw cAdvisor cgroup CPU, memory, OOM counter, and start time plus node_exporter CPU, available memory, and load. Add `internal/connector/runtime` as a typed orchestrator over the existing Prometheus and Loki connectors. It creates normalized requests with bounded time/series/sample budgets, correlates only on source-provided stable labels, hashes raw cgroup IDs for stable external identity, and marks raw cgroup-only evidence as unmapped. Kubernetes and mutation operations have explicit unsupported errors. No Docker API, socket, or privileged mount is introduced.

**Requirements**: Issue #13, Proposal #1, ADR 0003/0004/0005/0008 and repository `AGENTS.md`.

## Constraints

- Do not connect to Docker Socket or any Docker management API; do not expose container write operations.
- Do not infer a Compose service, host OS, healthy peer, exit, or root cause from raw cgroup paths or missing metrics.
- Preserve per-series identity and time; keep a replaced cgroup instance distinct by its source identity and observed start time.
- Include only evidence with validated source-provided labels. Explicitly report `raw_cgroup_only` mappings and absent event data.
- Use the existing outbound policy, SecretRef, bounded Prometheus/Loki connectors, and registered query templates.
- Reject Kubernetes-specific requests with `unsupported_runtime`; reject mutation requests before querying.

## Tasks

1. Add failing tests for registered runtime Prometheus templates, stable per-instance grouping, and rejection of unsupported mappings.
2. Add fixed cAdvisor and node_exporter metric templates and expressions without changing existing service templates.
3. Add a runtime collector that requests the fixed metric and lifecycle-log templates, merges by validated instance identity, describes query evaluation coverage and explicitly marks exporter scrape freshness unknown, and returns evidence gaps instead of health/zero defaults.
4. Add deterministic mock tests for separate raw cgroup observations (without healthy-peer claims), raw identity hashing, container replacement, missing/stale metrics, Loki event presence/absence, source links, budget bounds, Kubernetes rejection, and forbidden write operations.
5. Document the actual Compose/cgroup and Docker Desktop limitations in the plan and demo guide; verify the Compose topology does not mount a Docker Socket or add privileges.

## Validation

- Run focused datasource, Prometheus, Loki, and runtime collector tests, followed by race tests for the affected Go packages.
- Run `make check`, `gitleaks detect --source . --no-git --redact`, Compose config validation, and `git diff --check`.
- Use deterministic mock HTTP responses; do not depend on a live Docker daemon, Prometheus, Loki, or host kernel in unit tests.

## Risk and rollback

Risk is high because incorrect runtime identity can mislead incident diagnosis. The collector reports unverified identity as unmapped and missing observations as gaps. It is read-only, adds no migration, and rolls back by reverting the connector/templates/documentation commit.

## Ruling

- ADR 0005 establishes that the current cAdvisor setup has `raw_cgroup_only` data and cannot truthfully identify Compose service names, images, or lifecycle events. The implementation preserves that limitation and does not use Docker Socket access to manufacture identity. Any acceptance criterion requiring exact container-to-service mapping remains explicitly uncovered until a safe, verifiable mapping source is added.
- This PR is a foundation delivery (`Refs #13`), not completion of Issue #13. Raw labels, including `mapping_status=mapped`, are not an authenticated project/service identity contract. Until such a contract exists the collector never associates raw cgroups with a service or calls a comparison instance healthy.
- Aggregate query work is bounded across all seven metric templates; host filtering happens after source truncation, so source partial results remain partial. This collector is for an administrator-selected datasource, not a project authorization boundary.
- Lifecycle keyword matches remain unverified log observations even when nonempty. A Loki entry is associated with a container only when its `host_id` and `cgroup_id` labels exactly match the administrator's versioned mapping; the output contains the opaque container ID and mapping version, never the raw cgroup label. A `container_id` label or log text alone is not used for association. Start-time changes within a raw cgroup produce an explicit ambiguous-incarnation gap rather than attributing the whole window to its final start time.

- Regression tests reproduced and fixed: untrusted mapping labels, stale/future resource state, cancelled source calls, cross-host/unmapped log correlation, host-qualified identity, ambiguous start time, duplicate series, aggregate point and output entity budgets.
- Runtime templates use GET to match the existing demo read gateway. Existing service templates retain their POST behavior; their gateway compatibility is outside this foundation PR and remains a follow-up.
- The defaults are 10 series × 240 points per metric template. Seven-template aggregate planned points cannot exceed the shared 20,000-point budget. Resource entity collections are each capped by MaxSeries. Empty/missing start identity stays unknown; changing start values are preserved as samples, not collapsed to a final incarnation.

- Query evaluation timestamps do not establish exporter scrape freshness. Delay/Stale/LastObservedAt describe returned evaluation coverage only; every result discloses `exporter_scrape_freshness_unavailable`. Future-dated start evidence is retained with clock skew but cannot produce an instance identity. Regression tests failed before both fixes and passed afterward.

## Final local verification (2026-11-07)

- `go test -race ./internal/connector/runtime ./internal/connector/prometheus ./internal/datasource ./internal/connector/loki`: passed.
- `RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null make check`: passed (Go format/vet/tests/build, frontend lint/typecheck/tests/build, evaluation fixture and base Compose parse). No local database integration URL was configured; database integration remains a CI check.
- `gitleaks detect --source . --no-git --redact`: passed, no leaks found.
- Both base/demo Compose files parsed with required secret file paths set to `/dev/null` for configuration validation only. This is not a startup or fault-injection result.
- `git diff --check`: passed.
- Local Docker daemon is unavailable; real Compose smoke and demo fault validation were not run locally. Final-head CI and human review remain merge gates.
- Deferred Issue #13 acceptance: authenticated project/service/container mapping, verified lifecycle events, healthy-peer comparison, replacement history and memory-growth/restart fault exercise. This library is not yet connected to API/Agent/UI; these limitations are not treated as passed acceptance criteria.

## Independent review and integration (2026-11-08)

- Independent code review of the foundation scope returned `Approve with nits`; the future-start identity and exporter scrape freshness findings were fixed and independently checked. This is not full Issue #13 acceptance or human approval.
- Deferred nonblocking review note: duplicate metric-series detection includes `instance`, while raw cgroup merging uses host plus raw cgroup ID. The registered fixed container PromQL drops `instance`, so the current real connector path cannot produce the conflicting combination. Before widening the metrics-client contract, align these identity keys or validate the allowed result label shape.
- PR #44 was verified merged into `origin/main` at `8e07746259a0b91149af97b56b2baa49538f58f2`; the latest main was merged without conflicts. The merged GitHub connector adds no overlapping runtime changes. Final-head checks are rerun after integration.
