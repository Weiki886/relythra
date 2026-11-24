# Issue #95 Grafana native HMAC webhook slice for #16

## Scope

Make the existing Grafana webhook accept Grafana's native HMAC-SHA256 signature (`timestamp:body`, hexadecimal header) while preserving the existing Relythra-prefixed format. Both formats retain the five-minute timestamp bound, constant-time MAC comparison, bounded payload read and signature replay claim. Provision a demo-only Grafana webhook Contact Point and notification policy, then extend the isolated demo smoke to seed its own control-plane Project/Service fixtures, trigger an actual target-down alert and assert matching FIRING/RESOLVED Alert deliveries, one Investigation and linked Grafana Evidence are persisted by Relythra.

The demo generates an independent HMAC Secret file and mounts it only in API and Grafana. Grafana provisioning reads the exported bootstrap variable. Existing deployments must add the new Secret path before applying the overlay.

Native Grafana payloads include title/message/state/appVersion and per-alert ruleUID/orgId. Accept these bounded fields while continuing to reject unknown fields. HTTP source references are accepted only for literal 127.0.0.1 and ::1 so local demo links remain usable. Remote source references continue to require HTTPS. References are never fetched by ingestion.

Grafana process health can precede provisioning readiness. Use the existing bounded eventually helper around the dashboard, data source and alert-rule assertions.

The fault stage changes only inventory environment variables. Reuse the image built at initial startup with --no-build, avoiding a second remote Dockerfile frontend resolution during fault injection.

## Explicitly deferred

This slice does not trigger Prometheus, Loki, GitHub or Runtime collection after webhook receipt, create a diagnosis candidate from the alert, assert deployment evidence or complete Issue #16's slow-SQL end-to-end flow.

## Verification

- Unit/API tests verify Grafana-native timestamp-colon-body signatures, tamper and expiry rejection, legacy compatibility and replay rejection.
- `make demo-smoke` starts an isolated stack, provisions project/service fixtures, stops the demo inventory target, waits for a signed Grafana notification to persist, restores inventory, verifies the RESOLVED transition in the same Investigation and finishes existing telemetry/isolation checks.
- Run `make check`, Gitleaks and `git diff --check`, then check required remote CI.

## Rollback

Revert the API verifier, Grafana provisioning files, smoke assertions and documentation. No migration or persistent production data changes are added.
