# Issue #14 Deployment Candidate Evidence

## Scope and decisions

When Grafana ingestion creates an Investigation and links bounded deployment candidates, persist a snapshot of every linked deployment event as `DEPLOYMENT` Evidence in the same PostgreSQL transaction as alert and Grafana Evidence ingestion. Existing candidate matching semantics remain authoritative: time overlap creates a candidate, not proof that the deployment caused the alert. Persist every candidate when the match is ambiguous; do not choose a single deployment or increase any diagnostic confidence.

The snapshot reuses `DeploymentEvidence`, the configured redaction filter, append-only Evidence persistence, and existing candidate-to-incident ownership. No schema, API, connector, Agent, notification, or external-write behavior is added. This is a partial Issue #14 delivery and must use `Refs #14`.

## Implementation and verification

1. Add PostgreSQL integration tests that create two matching deployments then ingest and replay a firing alert; assert both candidate Evidence records are visible in the Investigation timeline and replay creates no duplicates.
2. Add a batch rollback test proving a later invalid alert rolls back the earlier alert and its candidate Evidence while leaving the pre-existing deployment event untouched.
3. Implement a transaction helper that loads only the Investigation incident's persisted deployment candidates, verifies candidate project/service/environment ownership, normalizes each event, and persists it through the existing immutable writer.
4. Call the helper from alert ingestion and manual remapping after candidate links are written and before commit.
5. Run focused PostgreSQL integration tests, Go race tests, repository checks, Gitleaks, and diff validation.

## Compatibility, risks, and rollback

Risk: high. This extends the existing alert-ingestion transaction with bounded local reads and writes, and may increase lock duration. Candidate selection is already capped at 100 per alert; evidence writes use the existing idempotent cap and ownership checks. No request/response or schema change is introduced. Roll back by reverting the PR; already persisted immutable snapshots remain in the timeline and are not deleted.
