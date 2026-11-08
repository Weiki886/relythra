package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestDomainSchemaMigratesAndRollsBack(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("RELYTHRA_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("RELYTHRA_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	adminDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open admin database: %v", err)
	}
	defer adminDB.Close()

	schema := fmt.Sprintf("relythra_schema_test_%d", time.Now().UnixNano())
	if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = adminDB.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	})

	testURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	query := testURL.Query()
	query.Set("search_path", schema)
	testURL.RawQuery = query.Encode()

	db, err := sql.Open("pgx", testURL.String())
	if err != nil {
		t.Fatalf("open isolated database: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	goose.SetBaseFS(Files)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set goose dialect: %v", err)
	}
	if err := goose.UpContext(ctx, db, "."); err != nil {
		t.Fatalf("run migrations from empty schema: %v", err)
	}
	if err := goose.UpContext(ctx, db, "."); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}
	assertEvaluationColumnsAbsent(t, ctx, db, schema)
	assertDeploymentIngestionSchema(t, ctx, db, schema)
	assertGrafanaAlertIngestionSchema(t, ctx, db, schema)
	assertEvidenceObservationSchema(t, ctx, db, schema)

	if err := goose.DownContext(ctx, db, "."); err != nil {
		t.Fatalf("roll back Evidence observation metadata migration: %v", err)
	}
	assertEvidenceObservationRolledBack(t, ctx, db, schema)
	if err := goose.DownContext(ctx, db, "."); err != nil {
		t.Fatalf("roll back Grafana alert ingestion migration: %v", err)
	}
	assertGrafanaAlertIngestionRolledBack(t, ctx, db, schema)
	if err := goose.DownContext(ctx, db, "."); err != nil {
		t.Fatalf("roll back deployment event ingestion migration: %v", err)
	}
	if err := goose.DownContext(ctx, db, "."); err != nil {
		t.Fatalf("roll back evaluation separation migration: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO diagnosis_cases (case_key, case_version, fault_type, title, expected_root_cause)
		VALUES ('preserve-before-migration', 1, 'slow-sql', 'Legacy answer', '{"category":"slow-sql"}'::jsonb)
	`); err != nil {
		t.Fatalf("insert legacy evaluation row: %v", err)
	}
	if err := goose.UpContext(ctx, db, "."); err == nil || !strings.Contains(err.Error(), "contains rows") {
		t.Fatalf("migration with legacy case data = %v, want an export-required error", err)
	}
	var preserved string
	if err := db.QueryRowContext(ctx, `SELECT expected_root_cause->>'category' FROM diagnosis_cases WHERE case_key = 'preserve-before-migration'`).Scan(&preserved); err != nil {
		t.Fatalf("verify legacy evaluation data is preserved: %v", err)
	}
	if preserved != "slow-sql" {
		t.Fatalf("legacy expected answer = %q, want preserved value", preserved)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM diagnosis_cases WHERE case_key = 'preserve-before-migration'`); err != nil {
		t.Fatalf("remove migration guard fixture: %v", err)
	}
	if err := goose.UpContext(ctx, db, "."); err != nil {
		t.Fatalf("apply evaluation separation after clearing fixture: %v", err)
	}
	assertEvaluationColumnsAbsent(t, ctx, db, schema)

	for _, table := range []string{
		"projects",
		"services",
		"releases",
		"deployment_events",
		"data_source_mappings",
		"alerts",
		"incidents",
		"investigations",
		"tool_calls",
		"evidence",
		"hypotheses",
		"diagnosis_cases",
		"reports",
		"notifications",
		"investigation_transition_audits",
		"deployment_candidates",
		"deployment_event_updates",
		"deployment_webhook_signatures",
		"alert_deliveries",
		"hypothesis_evidence",
		"audit_events",
	} {
		var relation *string
		if err := db.QueryRowContext(ctx, "SELECT to_regclass($1)::text", schema+"."+table).Scan(&relation); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if relation == nil {
			t.Errorf("table %s was not created", table)
		}
	}

	for _, trigger := range []string{
		"deployment_events_touch_updated_at",
		"investigations_transition_guard",
		"investigations_touch_updated_at",
		"tool_calls_reject_mutation",
		"evidence_reject_mutation",
		"hypotheses_reject_mutation",
		"reports_reject_mutation",
		"audit_events_reject_mutation",
		"deployment_event_updates_reject_mutation",
		"alert_deliveries_reject_mutation",
	} {
		var count int
		if err := db.QueryRowContext(ctx, `
			SELECT count(*)
			FROM pg_trigger trigger
			JOIN pg_class relation ON relation.oid = trigger.tgrelid
			JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
			WHERE trigger.tgname = $1
			  AND namespace.nspname = current_schema()
			  AND NOT trigger.tgisinternal
		`, trigger).Scan(&count); err != nil {
			t.Fatalf("check trigger %s: %v", trigger, err)
		}
		if count != 1 {
			t.Errorf("trigger %s count = %d, want 1", trigger, count)
		}
	}

	fixture := insertDomainFixture(t, ctx, db)
	assertDomainConstraints(t, ctx, db, fixture)
	var count int

	if err := goose.DownContext(ctx, db, "."); err != nil {
		t.Fatalf("roll back Evidence observation metadata migration: %v", err)
	}
	if err := goose.DownContext(ctx, db, "."); err != nil {
		t.Fatalf("roll back Grafana alert ingestion migration: %v", err)
	}
	if err := goose.DownContext(ctx, db, "."); err != nil {
		t.Fatalf("roll back deployment event ingestion migration: %v", err)
	}
	if err := goose.DownContext(ctx, db, "."); err != nil {
		t.Fatalf("roll back evaluation separation migration: %v", err)
	}
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'diagnosis_cases'
		  AND column_name = 'expected_root_cause'
	`, schema).Scan(&count); err != nil {
		t.Fatalf("check evaluation separation rollback: %v", err)
	}
	if count != 1 {
		t.Fatal("expected_root_cause was not restored by evaluation separation rollback")
	}
	if err := goose.DownContext(ctx, db, "."); err != nil {
		t.Fatalf("roll back datasource mapping constraints migration: %v", err)
	}
	count = 0
	if err := db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = 'data_source_mappings'
		  AND column_name = 'version'
	`).Scan(&count); err != nil {
		t.Fatalf("check mapping version rollback: %v", err)
	}
	if count != 0 {
		t.Fatal("data_source_mappings.version still exists after mapping constraints rollback")
	}
	if err := db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM pg_indexes
		WHERE schemaname = current_schema()
		  AND indexname = 'data_source_mappings_active_identity_idx'
	`).Scan(&count); err != nil {
		t.Fatalf("check mapping index rollback: %v", err)
	}
	if count != 0 {
		t.Fatal("active mapping unique index still exists after mapping constraints rollback")
	}
	var relation *string
	if err := db.QueryRowContext(ctx, "SELECT to_regclass($1)::text", schema+".projects").Scan(&relation); err != nil {
		t.Fatalf("check project before security rollback: %v", err)
	}
	if relation == nil {
		t.Fatalf("projects disappeared before security rollback")
	}

	if err := goose.DownContext(ctx, db, "."); err != nil {
		t.Fatalf("roll back security audit migration: %v", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT to_regclass($1)::text", schema+".audit_events").Scan(&relation); err != nil {
		t.Fatalf("check audit rollback: %v", err)
	}
	if relation != nil {
		t.Fatalf("audit_events still exists after security rollback")
	}
	if err := db.QueryRowContext(ctx, "SELECT to_regclass($1)::text", schema+".projects").Scan(&relation); err != nil {
		t.Fatalf("check project before domain rollback: %v", err)
	}
	if relation == nil {
		t.Fatalf("projects disappeared before domain rollback")
	}

	if err := goose.DownContext(ctx, db, "."); err != nil {
		t.Fatalf("roll back domain migration: %v", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT to_regclass($1)::text", schema+".projects").Scan(&relation); err != nil {
		t.Fatalf("check domain rollback: %v", err)
	}
	if relation != nil {
		t.Fatalf("projects still exists after domain rollback")
	}

	if err := goose.UpContext(ctx, db, "."); err != nil {
		t.Fatalf("reapply domain migration: %v", err)
	}
}

func assertEvidenceObservationSchema(t *testing.T, ctx context.Context, db *sql.DB, schema string) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'evidence'
		  AND column_name IN ('collected_at', 'query_parameters')
	`, schema).Scan(&count); err != nil {
		t.Fatalf("check Evidence observation columns: %v", err)
	}
	if count != 2 {
		t.Fatalf("Evidence observation columns = %d, want 2", count)
	}
	var collectedAtNullable string
	if err := db.QueryRowContext(ctx, `
		SELECT is_nullable FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'evidence' AND column_name = 'collected_at'
	`, schema).Scan(&collectedAtNullable); err != nil {
		t.Fatalf("read collected_at nullability: %v", err)
	}
	if collectedAtNullable != "YES" {
		t.Fatalf("collected_at is nullable = %q, want YES to preserve unknown historical collection time", collectedAtNullable)
	}
	var definition string
	if err := db.QueryRowContext(ctx, `
		SELECT pg_get_constraintdef(constraint_row.oid)
		FROM pg_constraint constraint_row
		JOIN pg_class relation ON relation.oid = constraint_row.conrelid
	JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
		WHERE namespace.nspname = $1 AND relation.relname = 'evidence'
		  AND constraint_row.conname = 'evidence_completeness_check'
	`, schema).Scan(&definition); err != nil {
		t.Fatalf("read Evidence completeness constraint: %v", err)
	}
	if !strings.Contains(definition, "EXPIRED") {
		t.Fatalf("EXPIRED is missing from Evidence completeness constraint: %s", definition)
	}
}

func assertEvidenceObservationRolledBack(t *testing.T, ctx context.Context, db *sql.DB, schema string) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'evidence'
		  AND column_name IN ('collected_at', 'query_parameters')
	`, schema).Scan(&count); err != nil {
		t.Fatalf("check Evidence observation rollback: %v", err)
	}
	if count != 0 {
		t.Fatalf("Evidence observation columns after rollback = %d, want 0", count)
	}
	var definition string
	if err := db.QueryRowContext(ctx, `
		SELECT pg_get_constraintdef(constraint_row.oid)
		FROM pg_constraint constraint_row
		JOIN pg_class relation ON relation.oid = constraint_row.conrelid
		JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
		WHERE namespace.nspname = $1 AND relation.relname = 'evidence'
		  AND constraint_row.conname = 'evidence_completeness_check'
	`, schema).Scan(&definition); err != nil {
		t.Fatalf("read rolled-back Evidence completeness constraint: %v", err)
	}
	if strings.Contains(definition, "EXPIRED") {
		t.Fatalf("EXPIRED remains after Evidence migration rollback: %s", definition)
	}
}

func assertGrafanaAlertIngestionSchema(t *testing.T, ctx context.Context, db *sql.DB, schema string) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'incidents' AND column_name = 'alert_id'
	`, schema).Scan(&count); err != nil {
		t.Fatalf("check incident alert reference: %v", err)
	}
	if count != 1 {
		t.Fatalf("incident alert reference count = %d, want 1", count)
	}
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'alert_deliveries'
		  AND column_name IN ('request_id', 'delivery_status', 'mapping_status', 'payload_hash', 'redacted_payload')
	`, schema).Scan(&count); err != nil {
		t.Fatalf("check Grafana alert delivery schema: %v", err)
	}
	if count != 5 {
		t.Fatalf("Grafana alert delivery columns = %d, want 5", count)
	}
}

func assertGrafanaAlertIngestionRolledBack(t *testing.T, ctx context.Context, db *sql.DB, schema string) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'alerts'
		  AND column_name IN ('fingerprint_version', 'event_version')
	`, schema).Scan(&count); err != nil {
		t.Fatalf("check Grafana alert column rollback: %v", err)
	}
	if count != 0 {
		t.Fatalf("Grafana-only alert columns after rollback = %d, want 0", count)
	}
	var relation *string
	if err := db.QueryRowContext(ctx, "SELECT to_regclass($1)::text", schema+".alert_deliveries").Scan(&relation); err != nil {
		t.Fatalf("check Grafana delivery table rollback: %v", err)
	}
	if relation != nil {
		t.Fatalf("alert_deliveries still exists after migration rollback")
	}
	var definition string
	if err := db.QueryRowContext(ctx, `
		SELECT pg_get_constraintdef(constraint_row.oid)
		FROM pg_constraint constraint_row
		JOIN pg_class relation ON relation.oid = constraint_row.conrelid
		JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
		WHERE namespace.nspname = $1 AND relation.relname = 'audit_events'
		  AND constraint_row.conname = 'audit_events_action_check'
	`, schema).Scan(&definition); err != nil {
		t.Fatalf("read rolled-back audit action constraint: %v", err)
	}
	if strings.Contains(definition, "alert.mapping.changed") {
		t.Fatalf("alert mapping audit action remains after rollback: %s", definition)
	}
}

func assertDeploymentIngestionSchema(t *testing.T, ctx context.Context, db *sql.DB, schema string) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'deployment_events'
		  AND column_name IN ('event_version', 'source_consistency', 'source_conflicts')
	`, schema).Scan(&count); err != nil {
		t.Fatalf("check deployment ingestion columns: %v", err)
	}
	if count != 3 {
		t.Fatalf("deployment ingestion columns = %d, want 3", count)
	}
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'deployment_webhook_signatures'
		  AND column_name IN ('signature_digest', 'expires_at', 'claimed_at')
	`, schema).Scan(&count); err != nil {
		t.Fatalf("check deployment signature replay columns: %v", err)
	}
	if count != 3 {
		t.Fatalf("deployment webhook signature columns = %d, want 3", count)
	}
}

func assertEvaluationColumnsAbsent(t *testing.T, ctx context.Context, db *sql.DB, schema string) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = $1
		  AND table_name = 'diagnosis_cases'
		  AND column_name = ANY($2)
	`, schema, []string{
		"injection_method",
		"expected_root_cause",
		"allowed_variants",
		"required_evidence",
		"counterexample_conditions",
		"healthy_baseline",
		"scenario_metadata",
	}).Scan(&count); err != nil {
		t.Fatalf("check evaluation-only diagnosis case columns: %v", err)
	}
	if count != 0 {
		t.Fatalf("runtime diagnosis_cases retained %d evaluation-only columns", count)
	}
}

type domainFixture struct {
	projectID          string
	serviceID          string
	releaseID          string
	incidentID         string
	investigationID    string
	startedAt          time.Time
	commitSHA          string
	deploymentEventKey string
	alertKey           string
}

func insertDomainFixture(t *testing.T, ctx context.Context, db *sql.DB) domainFixture {
	t.Helper()

	fixture := domainFixture{
		startedAt:          time.Date(2026, 11, 4, 5, 0, 0, 0, time.UTC),
		commitSHA:          strings.Repeat("a", 40),
		deploymentEventKey: "deploy-20261104-1",
		alertKey:           "grafana-alert-1",
	}
	if err := db.QueryRowContext(ctx, `
		INSERT INTO projects (slug, name)
		VALUES ('checkout', 'Checkout')
		RETURNING id::text
	`).Scan(&fixture.projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if err := db.QueryRowContext(ctx, `
		INSERT INTO services (project_id, slug, name)
		VALUES ($1, 'checkout-api', 'Checkout API')
		RETURNING id::text
	`, fixture.projectID).Scan(&fixture.serviceID); err != nil {
		t.Fatalf("insert service: %v", err)
	}
	if err := db.QueryRowContext(ctx, `
		INSERT INTO releases (
			project_id, service_id, version, commit_sha, image_digest, pull_requests
		) VALUES (
			$1, $2, 'v1.2.3', $3, $4, '[{"number":42,"url":"https://example.test/pull/42"}]'::jsonb
		)
		RETURNING id::text
	`, fixture.projectID, fixture.serviceID, fixture.commitSHA, "sha256:"+strings.Repeat("b", 64)).Scan(&fixture.releaseID); err != nil {
		t.Fatalf("insert release: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO deployment_events (
			project_id, service_id, release_id, environment, source_system,
			idempotency_key, status, started_at, finished_at, version, commit_sha,
			image_digest, instance_count, source_timezone, source_time_text
		) VALUES (
			$1, $2, $3, 'prod', 'ci', $4, 'SUCCEEDED', $5::timestamptz,
			$5::timestamptz + interval '2 minutes',
			'v1.2.3', $6, $7, 2, 'Asia/Shanghai', '2026-11-04T13:00:00+08:00'
		)
	`, fixture.projectID, fixture.serviceID, fixture.releaseID, fixture.deploymentEventKey,
		fixture.startedAt, fixture.commitSHA, "sha256:"+strings.Repeat("b", 64)); err != nil {
		t.Fatalf("insert deployment event: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO alerts (
			project_id, service_id, environment, fingerprint, idempotency_key,
			status, severity, summary, starts_at, labels, annotations
		) VALUES (
			$1, $2, 'prod', 'checkout-latency', $3, 'FIRING', 'ERROR',
			'Checkout latency is elevated', $4, '{"service":"checkout-api"}'::jsonb,
			'{"dashboard":"checkout"}'::jsonb
		)
	`, fixture.projectID, fixture.serviceID, fixture.alertKey, fixture.startedAt); err != nil {
		t.Fatalf("insert alert: %v", err)
	}
	if err := db.QueryRowContext(ctx, `
		INSERT INTO incidents (
			project_id, service_id, status, severity, summary, environment, started_at
		) VALUES (
			$1, $2, 'OPEN', 'ERROR', 'Checkout latency incident', 'prod', $3
		)
		RETURNING id::text
	`, fixture.projectID, fixture.serviceID, fixture.startedAt).Scan(&fixture.incidentID); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if err := db.QueryRowContext(ctx, `
		INSERT INTO investigations (incident_id, service_id, environment)
		VALUES ($1, $2, 'prod')
		RETURNING id::text
	`, fixture.incidentID, fixture.serviceID).Scan(&fixture.investigationID); err != nil {
		t.Fatalf("insert investigation: %v", err)
	}

	return fixture
}

func assertDomainConstraints(t *testing.T, ctx context.Context, db *sql.DB, fixture domainFixture) {
	t.Helper()

	assertStatementRejected(t, ctx, db, "duplicate deployment idempotency key", `
		INSERT INTO deployment_events (
			project_id, service_id, release_id, environment, source_system,
			idempotency_key, status, started_at, version, commit_sha
		) VALUES (
			$1, $2, $3, 'prod', 'ci', $4, 'SUCCEEDED', $5, 'v1.2.3', $6
		)
	`, fixture.projectID, fixture.serviceID, fixture.releaseID,
		fixture.deploymentEventKey, fixture.startedAt, fixture.commitSHA)

	assertStatementRejected(t, ctx, db, "duplicate alert idempotency key", `
		INSERT INTO alerts (
			project_id, service_id, environment, fingerprint, idempotency_key,
			status, severity, summary, starts_at
		) VALUES (
			$1, $2, 'prod', 'checkout-latency', $3, 'FIRING', 'ERROR',
			'Checkout latency is elevated', $4
		)
	`, fixture.projectID, fixture.serviceID, fixture.alertKey, fixture.startedAt.Add(time.Minute))

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin invalid transition transaction: %v", err)
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE investigations
		SET status = 'COMPLETED', completed_at = now(), version = 3
		WHERE id = $1
	`, fixture.investigationID)
	if err == nil {
		_ = tx.Rollback()
		t.Fatal("invalid investigation transition was accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback invalid transition: %v", err)
	}

	var status string
	var version int64
	if err := db.QueryRowContext(ctx, `
		SELECT status, version FROM investigations WHERE id = $1
	`, fixture.investigationID).Scan(&status, &version); err != nil {
		t.Fatalf("read investigation after rejected transition: %v", err)
	}
	if status != "RECEIVED" || version != 1 {
		t.Fatalf("rejected transition changed investigation: status=%s version=%d", status, version)
	}

	if _, err := db.ExecContext(ctx, `
		UPDATE investigations SET status = 'MATCHED', version = 2 WHERE id = $1
	`, fixture.investigationID); err != nil {
		t.Fatalf("apply MATCHED transition: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE investigations SET status = 'COLLECTING', version = 3 WHERE id = $1
	`, fixture.investigationID); err != nil {
		t.Fatalf("apply COLLECTING transition: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE investigations SET status = 'HYPOTHESIZING', version = 4 WHERE id = $1
	`, fixture.investigationID); err != nil {
		t.Fatalf("apply HYPOTHESIZING transition: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE investigations SET status = 'VERIFYING', version = 5 WHERE id = $1
	`, fixture.investigationID); err != nil {
		t.Fatalf("apply VERIFYING transition: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE investigations
		SET status = 'COMPLETED', completed_at = now(), version = 6
		WHERE id = $1
	`, fixture.investigationID); err != nil {
		t.Fatalf("apply COMPLETED transition: %v", err)
	}

	var auditCount int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM investigation_transition_audits WHERE investigation_id = $1
	`, fixture.investigationID).Scan(&auditCount); err != nil {
		t.Fatalf("count investigation transition audits: %v", err)
	}
	if auditCount != 6 {
		t.Fatalf("transition audit count = %d, want 6", auditCount)
	}
	assertStatementRejected(t, ctx, db, "terminal investigation mutation", `
		UPDATE investigations SET current_step = 'late-write' WHERE id = $1
	`, fixture.investigationID)
	_, err = db.ExecContext(ctx, `
		DELETE FROM investigations WHERE id = $1
	`, fixture.investigationID)
	var deleteError *pgconn.PgError
	if !errors.As(err, &deleteError) || deleteError.Code != "23503" {
		t.Fatalf("terminal investigation deletion error = %v, want SQLSTATE 23503", err)
	}

	var toolCallID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO tool_calls (investigation_id, tool_name)
		VALUES ($1, 'query_metric_template')
		RETURNING id::text
	`, fixture.investigationID).Scan(&toolCallID); err != nil {
		t.Fatalf("insert started tool call: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE tool_calls
		SET status = 'SUCCEEDED', completed_at = now(), result_summary = '{"series":3}'::jsonb
		WHERE id = $1
	`, toolCallID); err != nil {
		t.Fatalf("complete tool call: %v", err)
	}
	assertStatementRejected(t, ctx, db, "terminal tool call mutation", `
		UPDATE tool_calls SET query_text = 'late query' WHERE id = $1
	`, toolCallID)

	var evidenceID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO evidence (
			investigation_id, tool_call_id, source_type, entity_type, entity_id,
			observed_start, observed_end, query_text, value_summary, completeness,
			independence_group, content_hash
		) VALUES (
			$1, $2, 'PROMETHEUS', 'service', $3, $4::timestamptz,
			$4::timestamptz + interval '5 minutes',
			'latency_p95{service="checkout-api"}', '{"p95_ms":420}'::jsonb,
			'COMPLETE', 'metrics', $5
		)
		RETURNING id::text
	`, fixture.investigationID, toolCallID, fixture.serviceID, fixture.startedAt,
		strings.Repeat("c", 64)).Scan(&evidenceID); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}
	assertStatementRejected(t, ctx, db, "evidence mutation", `
		UPDATE evidence SET value_summary = '{"p95_ms":1}'::jsonb WHERE id = $1
	`, evidenceID)

	var hypothesisID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO hypotheses (
			investigation_id, rank, entity, fault_type, mechanism,
			trigger_change, affected_scope, confidence, summary
		) VALUES (
			$1, 1, 'checkout-api', 'slow-sql', 'inefficient query',
			'release v1.2.3', 'prod', 'HIGH', 'New query path increased latency'
		)
		RETURNING id::text
	`, fixture.investigationID).Scan(&hypothesisID); err != nil {
		t.Fatalf("insert hypothesis: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO hypothesis_evidence (
			investigation_id, hypothesis_id, evidence_id, stance
		) VALUES ($1, $2, $3, 'SUPPORTS')
	`, fixture.investigationID, hypothesisID, evidenceID); err != nil {
		t.Fatalf("link hypothesis evidence: %v", err)
	}
	assertStatementRejected(t, ctx, db, "hypothesis mutation", `
		UPDATE hypotheses SET confidence = 'LOW' WHERE id = $1
	`, hypothesisID)

	var reportID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO reports (
			investigation_id, result_status, confidence, summary, timeline
		) VALUES (
			$1, 'COMPLETED', 'HIGH', 'Release introduced an inefficient query',
			'[{"at":"2026-11-04T05:00:00Z","kind":"deployment"}]'::jsonb
		)
		RETURNING id::text
	`, fixture.investigationID).Scan(&reportID); err != nil {
		t.Fatalf("insert report: %v", err)
	}
	assertStatementRejected(t, ctx, db, "report mutation", `
		UPDATE reports SET summary = 'rewritten report' WHERE id = $1
	`, reportID)
}

func assertStatementRejected(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	label string,
	statement string,
	args ...any,
) {
	t.Helper()
	if _, err := db.ExecContext(ctx, statement, args...); err == nil {
		t.Fatalf("%s was accepted", label)
	}
}
