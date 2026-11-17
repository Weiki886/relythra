# Issue #15 deterministic slow-query rule plan

## Goal

Add the first deterministic v0 diagnosis rule: emit a traceable database
performance candidate only when slow-query log evidence and database latency
metric evidence overlap for the same mapped service.

## Scope

- Add a pure analysis package that consumes normalized persisted Evidence DTOs.
- Match only the registered v1 database-latency and slow-query templates.
- Require evidence to belong to one Investigation, identify the same SERVICE,
  have overlapping observation windows, and contain actual in-window samples
  and log entries.
- Return a versioned candidate with stable rule ID, support Evidence IDs and a
  conservative confidence label; otherwise return `INCONCLUSIVE` with missing
  evidence requirements.
- Do not attribute the candidate to a deployment, define unapproved numeric
  thresholds, persist hypotheses, add API routes, or change the UI.

## Files

- Add `internal/diagnosis/rules.go` and its tests.
- Add this plan and execution record.

## Verification plan

1. Add failing tests for a correlated pair, partial evidence, missing sources,
   non-overlapping timestamps, mismatched service entities and invalid
   Investigation ownership.
2. Implement the pure rule evaluator and deterministic output ordering.
3. Run focused tests, the relevant race tests, full `make check` with the local
   isolated PostgreSQL test URL, Gitleaks and `git diff --check`.
4. Review and open a PR with `Refs #15`, M2 and matching type/risk/area labels.
   Do not merge or close Issue #15.

## Risk and rollback

Standard risk: an additive pure function with no writes, migration, external
requests or runtime wiring. Reverting the package and tests removes the rule;
there is no persisted state to clean up.

## Execution record

- RED: `go test ./internal/diagnosis -count=1` failed to compile because the
  analysis API and rule types did not exist yet.
- GREEN: the focused diagnosis tests pass after implementing the pure rule
  evaluator. Cases cover a correlated pair, cross-service evidence, disjoint
  observation windows, out-of-window logs, partial evidence, missing sources,
  and Investigation ownership.
- Ruling: when multiple evidence pairs exist for one service, a complete pair
  preserves `MEDIUM` confidence even if other pairs are partial. A regression
  test failed before this adjustment and passes afterward.
- The output deliberately uses symptom language (`DATABASE_PERFORMANCE`),
  stable Evidence references, and no deployment attribution or numeric
  threshold. Unsupported templates are ignored; malformed recognized evidence
  is rejected as invalid input.
- Final validation passed after the last rule/test change:
  `go test -race ./internal/diagnosis -count=1`; full `make check` with an
  isolated local PostgreSQL test schema; `gitleaks dir --no-banner --redact`;
  and `git diff --check`.
