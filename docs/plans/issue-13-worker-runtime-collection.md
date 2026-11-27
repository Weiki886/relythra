# Issue #13 Worker Runtime Evidence Collection Plan

## Goal

Connect the existing bounded Docker Compose runtime collector to the investigation collection Worker. For an exact service/environment mapping, persist its host/container/lifecycle Runtime Evidence before completing the collection lease. Preserve the current no-Docker-Socket and fixed-template read-only boundary.

This is a partial delivery (`Refs #13` and `Refs #16`): it adds automatic runtime collection but does not claim verified lifecycle events, healthy-peer status, memory-growth diagnosis, or the complete slow SQL release chain.

## Decisions and boundaries

- Reuse `internal/connector/runtime` and `PersistRuntimeEvidence`; do not add another runtime query implementation or schema migration.
- A Runtime mapping authorizes the complete registered bundle `runtime.containers.v1`, `runtime.host.v1`, and `runtime.events.v1`, because the current collector emits the bundle atomically.
- Resolve the project/service/environment-scoped Prometheus and Loki mappings as the runtime collector's underlying query targets, passing each SecretRef through for the existing connector to resolve and redact. The Runtime mapping's complete high-level bundle authorizes the collector's statically defined underlying Prometheus/Loki templates; those implementation templates are not exposed as independent service-level queries. Do not derive new URLs or accept arbitrary query strings.
- If the Runtime bundle or backing telemetry mapping is missing/ambiguous, persist bounded Runtime collection-gap Evidence and continue the task without silently inferring healthy state. Underlying per-template failures remain in the Runtime result and are persisted with the result.
- Bind persistence to the current investigation, service and collection timestamp; do not write the collection job ID into `tool_call_id`, whose foreign key represents an Agent tool call. Existing Evidence content-hash replay makes retries idempotent. Runtime Evidence is saved before the lease is completed; save failure retries the task.
- Never call Docker APIs, add permissions, change mappings, or perform recovery actions.

## Files and implementation steps

1. `internal/worker/collection_test.go`: add failing maintained-code tests for configured Runtime collection, exact source/template scope, missing/ambiguous dependencies, failed Runtime query, persistence-before-completion and persistence failure retry.
2. `internal/worker/collection.go`: add the Runtime collector interface/option, dispatch, deterministic dependency selection, fixed-template and SecretRef checks, bounded request construction, structured missing-mapping gaps, and atomic Runtime Evidence persistence.
3. `cmd/relythra-worker/main.go`: assemble the Runtime collector from the already configured Prometheus and Loki connectors.
4. `docs/adr/0010-investigation-collection-dispatch.md`, `docs/demo.md` and repository `AGENTS.md`: describe when the Worker emits Runtime Evidence and the required mapping/template bundle; keep demo claims limited to configurations actually exercised.

## Ruling

The first implementation plan required adding seven internal Runtime Prometheus templates and a lifecycle template to the standalone Prometheus/Loki mappings. Source inspection showed the Worker would also dispatch those templates through ordinary service-level persistence, where host/cgroup measurements would be attributed to the service entity and host/runtime selectors would be wrong. The Runtime high-level template bundle is the authorization boundary for its static underlying query bundle; source mappings provide only scoped endpoint and SecretRef. This avoids duplicate misattributed evidence and keeps the registered Runtime contract bounded.

## Validation

- Run each new regression test red before implementation and green afterward.
- Run focused `go test ./internal/worker ./internal/connector/runtime ./internal/evidence ./internal/store`.
- Run `make check`, `gitleaks dir --no-banner --redact .`, and `git diff --check`.
- Verify Compose configuration remains free of Docker Socket and privileged mounts; the change adds no runtime authority or migration.
- Remote Backend, Frontend, and Compose smoke remain separate PR merge gates.

## Risk and rollback

Risk: `high` because this activates runtime evidence in the collection path and combines multiple telemetry sources. Labels: `type:feature`, `high`, `area:connector`, `area:backend`, `area:security`. No persistence schema changes. Reverting the PR restores the current explicit unsupported-source gaps.
