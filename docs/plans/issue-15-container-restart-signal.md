# Issue #15 container restart signal

## Scope and plan

Risk is high because the public diagnosis response adds an entity type and new candidate semantics.

Add one v0 rule using persisted Docker Compose runtime Evidence. The rule correlates a change in the raw Prometheus container start-time samples with an unverified Loki lifecycle match for the same explicitly mapped container, host, service, environment, and mapping version. A start change is eligible only when the reported start time is after the previous metric evaluation and no later than the current evaluation. Correlate that reported start time—not the metric evaluation timestamp—with the log. Both timestamps must fall inside the intersection of the two Evidence observation windows and within five minutes of each other.

The candidate is `LOW`, identifies the opaque `CONTAINER` entity and cites both source Evidence IDs. The lifecycle log remains unverified, independent restart corroboration is absent, and restart causality remains unknown. Stale, incomplete, ambiguous, regressing, malformed, raw-cgroup-only, mismapped, clock-skewed, or out-of-window observations do not produce a candidate. The collector's existing behavior is preserved: changing start-time samples remain raw evidence and do not yield a unique `StartTime` or `InstanceID`.

Affected files: diagnosis rule/tests, diagnosis API integration test, frontend candidate decoder/display/tests, and README semantics. No connector query, deployment attribution, automatic operation, schema or persistence behavior changes.

## Verification

- Table-driven rule tests cover corroborated evidence, unchanged start time, unmapped identity, mismatched container, disjoint/overlapping evidence windows, delayed evaluation versus actual start, and contradictory samples.
- A PostgreSQL-backed integration test runs controlled Prometheus and Loki responses through `runtime.Collector.Query`, persists the emitted runtime Evidence, and calls the diagnosis API. It verifies the collector leaves `StartTime` unset and returns an opaque container ID.
- Frontend tests cover bounded container IDs, invalid controls/entities, and legacy known rules that predate `entity_type`.
- Run `make check`, targeted database-backed Go tests, Gitleaks, `git diff --check`, and required remote CI.

## Rollback

Revert this PR and restore rule-set version `v0.4.0` and the prior candidate entity-type contract. No migration or persisted record format changes are introduced; earlier Evidence remains readable.
