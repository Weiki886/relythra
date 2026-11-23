# Issue #16 Prometheus and Loki timeline slice

## Scope

Add a PostgreSQL-backed integration test that passes bounded Prometheus and
Loki connector result snapshots through the existing Evidence persistence
methods and reads them through the Investigation timeline API. The assertions
cover source identity, UTC observation ordering, canonical service ownership,
independence groups, and preserved metric/log summaries.

The test uses deterministic connector result fixtures. The connector packages
separately test fixed template execution and bounded HTTP behavior; the Compose
smoke separately checks real Prometheus and Loki operation. This slice does not
claim that a webhook automatically invokes either connector or that the complete
slow-SQL diagnosis flow is finished.

## Verification

Run the focused integration test against an isolated PostgreSQL 17 instance,
then run `make check`, Gitleaks, and the required remote CI checks. The database
fixture creates and drops its own schema.

## Rollback

Revert the test and this plan. No application behavior, migration, or persistent
data is changed.
