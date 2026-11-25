# Issue #16: combine deployment, alert, telemetry and diagnosis evidence

## Scope

Add one PostgreSQL-backed integration test that composes existing public
DeploymentEvent and signed Grafana webhook ingestion with bounded Prometheus,
Loki and deployment-linked GitHub result fixtures. Read the resulting diagnosis
and timeline through the public read-only API and assert that all five evidence
sources belong to the same Investigation, the slow-query candidate cites the
expected metric and log observations, its confidence remains `MEDIUM`, and
source references are available on the timeline.

The test uses the existing isolated-schema database helper. Project, Service
and Release rows are setup configuration; deployment and alert facts enter
through their HTTP webhooks; evidence uses the existing validated persistence
methods. It does not call remote services, inject a Compose fault, or claim that
webhook receipt automatically schedules connector collection. Those remain
unverified parts of Issue #16.

## Plan

1. Add the integration test in `internal/api/slow_sql_integration_test.go`.
2. Confirm it runs against the local PostgreSQL test database using an isolated
   migrated schema, and assert both diagnosis output and timeline sources.
3. Run the API, Evidence and store test suites, the repository checks, Gitleaks
   and diff validation.

## Risk and rollback

Risk: `standard`; this is test-only and uses the existing isolated schema
fixture, with no production code, migration, external write, or new dependency.
Revert the test and this plan to roll it back.

## Execution record

- Focused test: `RELYTHRA_TEST_DATABASE_URL='postgres:///relythra?host=/tmp&sslmode=disable' go test ./internal/api -run '^TestSlowSQLDeploymentAlertEvidenceDiagnosisTimelineIntegration$' -count=1 -v` passed against PostgreSQL 17. It applied migrations in a per-test schema and cleaned the schema afterward.
- `GOCACHE=/private/tmp/relythra-issue16-go-cache RELYTHRA_TEST_DATABASE_URL='postgres:///relythra?host=/tmp&sslmode=disable' go test -race ./internal/api ./internal/evidence ./internal/store -count=1`: passed against the local PostgreSQL 17 test database; each integration test uses a temporary schema.
- `RELYTHRA_MANAGEMENT_TOKEN_FILE=/dev/null RELYTHRA_POSTGRES_PASSWORD_FILE=/dev/null make check`: passed, including Go vet/tests/build, ESLint, TypeScript, 57 Vitest tests, production build, diagnosis case validation, 16 demo-artifact tests, Compose config rendering and local startup-script checks. The production build reports the existing ECharts chunk-size warning.
- `gitleaks detect --no-git --source . --redact --no-banner`, `gofmt -d internal/api/slow_sql_integration_test.go` and `git diff --check`: passed.
- Compose smoke / live fault injection was not run. The test uses controlled source snapshots and does not verify automatic connector scheduling.
