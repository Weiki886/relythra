# Issue #16 Slow SQL Workload Slice

## Scope

Make the existing test-only slow SQL operation affect the normal
`orders -> inventory -> demo PostgreSQL` request path when
`DEMO_ENABLE_FAULTS=true`. Extend the disposable demo smoke to switch between
baseline and fault releases, verify latency in Prometheus and SQL duration in
Loki, then restore and verify the baseline again.

The fault remains off by default, accepts no SQL text or command from a caller,
uses the existing fixed `pg_sleep(0.2)` statement, and runs only in the demo
inventory service. The smoke uses its own Compose project, ports, secrets and
volumes and always tears them down.

## Explicitly Deferred

- Triggering and receiving a real Grafana latency alert.
- Automatically collecting Prometheus, Loki, GitHub, DeploymentEvent and
  Runtime evidence for an Investigation.
- Generating or validating a Relythra diagnosis candidate from the demo fault.
- Treating the fixed delay fixture as an inefficient SQL query-plan regression.

These require the separately tracked collection orchestration path. This PR
references Issue #16 but does not satisfy or close the complete E2E acceptance.

## Verification

- Unit test proves the slow query runs on inventory `/stock` only when the
  explicit fault switch is enabled.
- `make demo-smoke` sends real orders requests during fault and recovery, then
  checks the orders latency histogram and inventory request-duration logs.
- The existing disposable-stack teardown remains responsible for cleanup.

## Rollback

Revert the application, smoke and documentation changes. No schema, persistent
volume or production configuration changes are introduced.
