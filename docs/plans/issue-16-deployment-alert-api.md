# Issue #16 deployment and alert API integration slice

## Scope and plan

Add a PostgreSQL-backed API integration test for the existing deployment and
Grafana webhook ingestion path. Create Project, Service and Release fixtures in
an isolated migrated schema because the repository has no public management API
for these records. Submit a signed deployment event and a signed Grafana alert
through their HTTP handlers, then read the investigation timeline and verify
that the alert and matching deployment evidence refer to the expected sources.
Check replay rejection and repeat delivery with a fresh signature to verify
that an existing investigation is reused without duplicating evidence.

The test is limited to `internal/api` and this plan. It does not impersonate an
actual Grafana server, trigger a slow SQL fault, or simulate collected metrics,
logs, source-code changes or a diagnosis. These remain part of Issue #16.

## Verification and rollback

Run the targeted test against an isolated PostgreSQL 17 instance using
`RELYTHRA_TEST_DATABASE_URL`, then run `make check` and the remote required CI.
Review the change for test isolation and credential handling. Revert the test and
this document to roll back; no application behavior or schema is changed.
