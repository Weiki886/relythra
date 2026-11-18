# Issue #15: Read-only diagnosis API

## Scope and contract

- Add `GET /api/v1/investigations/{id}/diagnosis` using the existing read API boundary. Reject query strings, including filters and pagination, with `400`; reject non-GET methods with `405` and invalid IDs with `400`, before reading storage.
- Read the unfiltered Investigation timeline once with limit 100 and offset 0. The existing store uses a read-only repeatable-read transaction for the count and page. Do not join separately paginated snapshots.
- Return the standard `data` / `request_id` envelope. `data` contains `investigation_id`, `evidence_total`, `evidence_limit`, `evidence_truncated`, and the existing analysis fields `rule_set_version`, `status`, `candidates`, `missing_requirements`.
- If any records were omitted, return `INCONCLUSIVE`, empty candidates and `complete_evidence_snapshot` as a missing requirement. Do not analyze a selected subset. Empty investigations return the normal evidence-insufficient analysis. Missing investigations return `404`.
- Convert stored Evidence to the narrow diagnosis DTO without raw references, query text, log lines or relation payloads in the response. Invalid persisted rule input is a server error (`500`), not a caller error; existing sanitized error handling applies.
- Accept only known completeness states. `MISSING` and `EXPIRED` never support a candidate even if a persisted summary retains observations. `PARTIAL` remains eligible only for lower-confidence support. Bump rule-set version to `v0.1.1` for this semantics correction.
- Candidates describe database-performance symptoms with Evidence IDs and qualitative confidence. They do not establish an anomalous latency threshold, slow SQL causality, deployment cause or calibrated probability.

## Implementation sequence

1. Add failing completeness regression tests in `internal/diagnosis/rules_test.go` and HTTP contract tests in `internal/api/diagnosis_handler_test.go`. Run focused tests and record RED evidence.
2. Update `internal/diagnosis/rules.go`, register the route in `internal/api/handler.go`, and implement `internal/api/diagnosis_handler.go` using the existing Reader and rule engine. No connector calls or data writes.
3. Add `internal/api/diagnosis_integration_test.go` with a dedicated schema using the existing store tests' isolation pattern and persisted normalized Evidence. Verify eligible and expired observations through the real Reader, plus the exact 100/101-record boundary.
4. Document the endpoint, evidence cap and interpretation limits in `README.md`.
5. Run focused tests with the local isolated PostgreSQL test harness, race checks, `make check`, Gitleaks and diff checks; review the final diff and create an English-titled PR with Chinese details and `Refs #15` under M2. Confirm required CI at the pushed HEAD.

## Boundaries and rollback

- Risk: high (new public read API). Preserve the existing local/trusted-network read access model; no new authentication mechanism or production exposure claim.
- No schema, configuration, dependency or deployment-order changes. No hypothesis/report persistence, worker orchestration, frontend, LLM, notification or external side effects.
- Rollback: revert this PR and redeploy the previous application. Persisted Evidence is unchanged. Existing read endpoints remain compatible.
- Issue #15 remains open: other rules, fault detail UI and broader acceptance are outside this PR. Human review and explicit merge authorization remain required.
