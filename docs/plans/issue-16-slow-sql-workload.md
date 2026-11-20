# Issue #16 Slow SQL Workload Slice

## Scope

Capture diagnostics when the existing disposable demo smoke fails, before the
Compose project and temporary secrets are removed. Preserve the failing stage
and exit status, bounded Compose status and service logs, fixed Prometheus and
Loki queries with their request URLs, and Grafana health. Redact the generated
credentials and common sensitive fields, restrict local file permissions, and
upload the bundle for failed GitHub Actions demo runs with short retention.

Affected files are `scripts/demo-smoke.sh`, `scripts/demo_artifacts.py` and its
unit tests, `Makefile`, `.github/workflows/ci.yml`, and `docs/demo.md`. The
collector uses the existing isolated smoke project and never changes the
Relythra diagnostic API or shared environments.

## Explicitly Deferred

- Triggering and receiving a real Grafana latency alert.
- Automatically collecting Prometheus, Loki, GitHub, DeploymentEvent and
  Runtime evidence for an Investigation.
- Generating or validating a Relythra diagnosis candidate from the demo fault.
- Treating the fixed delay fixture as an inefficient SQL query-plan regression.
- Capturing Grafana screenshots or Investigation IDs; the automatic alert and
  Investigation path is not implemented yet.

These require the separately tracked collection orchestration path. This PR
references Issue #16 but does not satisfy or close the complete E2E acceptance.

## Verification

- `make demo-artifact-check` exercises redaction, bounded capture, source
  availability, and cleanup after an injected smoke failure.
- On failure, the smoke writes bounded Compose status/logs and live Prometheus/
  Loki responses into a private local diagnostics directory before teardown.
- The existing disposable-stack teardown remains responsible for cleanup.

## Rollback

Revert this PR to restore the previous smoke cleanup and CI workflow. No schema,
persistent volume or production configuration changes are introduced.
