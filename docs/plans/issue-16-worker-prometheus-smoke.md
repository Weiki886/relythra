# Issue #16 Worker Prometheus smoke slice

## Goal

Extend the isolated demo smoke so a signed Grafana FIRING delivery has an Inventory Prometheus mapping and the public Investigation timeline eventually contains non-empty latency Evidence collected by the Worker.

## Scope and affected files

- `scripts/demo-assert.py`: add an authenticated mapping setup mode using the temporary management token and a bounded timeline assertion mode using the existing read-only API helper.
- `scripts/demo_artifacts_test.py`: cover valid Evidence and rejection of a wrong investigation ID, wrong template, empty series, or empty samples.
- `scripts/demo-smoke.sh`: create the mapping after seeding the isolated service and assert Worker Evidence for the FIRING Investigation before restoring Inventory.
- `docs/demo.md`: describe exactly which automatic evidence path the smoke now verifies and retain the limits of the still-unimplemented full v0 chain.

## Implementation sequence

1. Add a pure timeline validation test and run it to confirm the missing behavior fails.
2. Implement narrowly bounded timeline validation for `investigation_id`, `source_type`, `query_parameters.template_id`, and at least one `value_summary.series[].samples[]` item.
3. Add the smoke mapping through `POST /api/v1/data-source-mappings` with project/service IDs queried from the isolated database, `environment=demo`, endpoint `http://observability-gateway:9090`, fixed template `prometheus.service.latency.v1`, and the existing file SecretRef. Never print the management or observability token.
4. Before stopping Inventory, send `/orders` requests across multiple Prometheus scrape intervals and wait for the fixed latency query to return a finite positive value; this prevents a lazy histogram from remaining flat and producing only NaN results.
5. After observing the signed FIRING delivery, poll the public timeline endpoint with a bounded timeout and fail with the last missing-evidence reason if the Worker does not persist a populated Prometheus result.
6. Update demo documentation to distinguish the newly verified Worker Prometheus evidence from the remaining unverified GitHub, Loki-to-Investigation, runtime, and diagnosis-candidate chain.

## Verification

- Run the pure assertion tests and `make demo-artifact-check`.
- Run `bash -n scripts/demo-smoke.sh`, `git diff --check`, `make check`, and Gitleaks.
- Run `make demo-smoke` if the local container engine and image registry are available; otherwise report the exact blocking environment evidence. The script must use its own random Compose project and existing disposable cleanup path.
- Inspect the final PR metadata and ensure it uses `Refs #16`, the Issue's M2 milestone, and the applicable `type:test`, `standard`, and `area:qa` labels.

## Risks and rollback

This is a test-only change against the already isolated demo stack. The mapping is created via the authenticated management API, the Worker reads a temporary least-scope observability token, and the diagnostic API remains read-only. Revert the PR to restore the previous smoke behavior; no migration, persistent shared resource, or production setting changes are introduced.

## Rulings

- Keep the Issue open: this slice proves the Worker-to-Prometheus-to-Investigation timeline path but does not prove the complete required v0 chain.
- Accept PR #105 review feedback: Inventory creates its histogram series lazily, so the smoke must warm it across scrape intervals and require a finite positive latency query before stopping Inventory.
