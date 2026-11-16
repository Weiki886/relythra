package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/pressly/goose/v3"
)

func TestIngestGrafanaAlertsPersistsEvidenceAtomically(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	repository := NewPostgres(db)
	fixture := insertStoreFixture(t, ctx, db, "grafana-ingest-evidence")
	filter := mustGrafanaEvidenceFilter(t, "private-secret")
	input := fixtureAlertInput(fixture, "grafana-ingest-evidence-fingerprint")
	input.ProjectSlug = "grafana-ingest-evidence"
	input.SourceReference = "https://example.com/alerts/evidence"
	input.SourceTimezone = "Asia/Shanghai"
	input.SourceTimeText = "2026-11-04T13:00:00+08:00"
	input.Summary = "Checkout private-secret latency alert"

	if _, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "evidence-missing-filter", nil); !errors.Is(err, redact.ErrUnsafeOutput) {
		t.Fatalf("ingest without redaction filter = %v, want ErrUnsafeOutput", err)
	}
	results, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "evidence-firing", filter)
	if err != nil {
		t.Fatalf("ingest firing alert: %v", err)
	}
	if len(results) != 1 || results[0].InvestigationID == "" {
		t.Fatalf("firing result = %+v, want linked investigation", results)
	}

	assertGrafanaEvidenceCount(t, ctx, db, results[0].InvestigationID, 1)
	if _, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "evidence-firing-replay", filter); err != nil {
		t.Fatalf("replay firing alert: %v", err)
	}
	assertGrafanaEvidenceCount(t, ctx, db, results[0].InvestigationID, 1)

	endedAt := fixture.startedAt.Add(5 * time.Minute)
	input.Status = "RESOLVED"
	input.EndsAt = &endedAt
	resolved, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "evidence-resolved", filter)
	if err != nil {
		t.Fatalf("ingest resolved alert: %v", err)
	}
	if len(resolved) != 1 || resolved[0].InvestigationID != results[0].InvestigationID {
		t.Fatalf("resolved result = %+v, want original investigation %s", resolved, results[0].InvestigationID)
	}
	timeline, err := repository.GetInvestigationTimeline(ctx, results[0].InvestigationID, InvestigationTimelineFilter{SourceType: "GRAFANA"}, 10, 0)
	if err != nil {
		t.Fatalf("read Grafana timeline: %v", err)
	}
	if timeline.Total != 2 || len(timeline.Items) != 2 {
		t.Fatalf("timeline has %d items (%d total), want firing and resolved snapshots", len(timeline.Items), timeline.Total)
	}
	if !strings.Contains(string(timeline.Items[0].Evidence.ValueSummary), `"status": "FIRING"`) ||
		!strings.Contains(string(timeline.Items[1].Evidence.ValueSummary), `"status": "RESOLVED"`) {
		t.Fatalf("timeline does not preserve both statuses: %+v", timeline.Items)
	}
	if strings.Contains(string(timeline.Items[0].Evidence.ValueSummary), "private-secret") || strings.Contains(string(timeline.Items[1].Evidence.ValueSummary), "private-secret") {
		t.Fatal("evidence contains the unredacted annotation secret")
	}
	if timeline.Items[0].Evidence.IndependenceGroup != timeline.Items[1].Evidence.IndependenceGroup {
		t.Fatalf("status snapshots have different independence groups: %q != %q", timeline.Items[0].Evidence.IndependenceGroup, timeline.Items[1].Evidence.IndependenceGroup)
	}

	rollback := fixtureAlertInput(fixture, "grafana-ingest-evidence-rollback")
	rollback.ProjectSlug = "grafana-ingest-evidence"
	invalid := rollback
	invalid.ProjectSlug = "missing-project"
	if _, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{rollback, invalid}, "evidence-batch-rollback", filter); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed batch ingestion = %v, want ErrNotFound", err)
	}
	var alerts, evidenceCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM alerts WHERE fingerprint=$1`, rollback.Fingerprint).Scan(&alerts); err != nil {
		t.Fatalf("count rolled back alert: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM evidence WHERE source_type='GRAFANA'`).Scan(&evidenceCount); err != nil {
		t.Fatalf("count evidence after rollback: %v", err)
	}
	if alerts != 0 || evidenceCount != 2 {
		t.Fatalf("rollback state: alerts=%d evidence=%d, want 0 and 2", alerts, evidenceCount)
	}
}

func TestIngestGrafanaAlertsPersistsDeploymentCandidateEvidence(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	repository := NewPostgres(db)
	fixture := insertStoreFixture(t, ctx, db, "grafana-deployment-evidence")
	deploymentInput := fixture.deploymentInput("grafana-deployment-evidence-1")
	deploymentInput.SourceReference = "https://example.com/deployments/1"
	deployment, created, err := repository.CreateDeploymentEvent(ctx, deploymentInput)
	if err != nil || !created {
		t.Fatalf("create deployment event: created=%v err=%v", created, err)
	}
	secondDeploymentInput := fixture.deploymentInput("grafana-deployment-evidence-2")
	secondDeploymentInput.SourceReference = "https://example.com/deployments/2"
	secondDeployment, created, err := repository.CreateDeploymentEvent(ctx, secondDeploymentInput)
	if err != nil || !created {
		t.Fatalf("create second deployment event: created=%v err=%v", created, err)
	}
	filter := mustGrafanaEvidenceFilter(t)
	input := fixtureAlertInput(fixture, "grafana-deployment-evidence-alert")
	input.ProjectSlug = "grafana-deployment-evidence"
	results, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "grafana-deployment-evidence-request", filter)
	if err != nil {
		t.Fatalf("ingest Grafana alert: %v", err)
	}
	if len(results) != 1 || results[0].InvestigationID == "" || results[0].DeploymentCount != 2 {
		t.Fatalf("ingestion result = %+v, want one investigation and both deployment candidates", results)
	}
	assertDeploymentEvidence(t, ctx, db, results[0].InvestigationID, deployment.ID, 1)
	assertDeploymentEvidence(t, ctx, db, results[0].InvestigationID, secondDeployment.ID, 1)

	if _, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "grafana-deployment-evidence-replay", filter); err != nil {
		t.Fatalf("replay Grafana alert: %v", err)
	}
	assertDeploymentEvidence(t, ctx, db, results[0].InvestigationID, deployment.ID, 1)
	assertDeploymentEvidence(t, ctx, db, results[0].InvestigationID, secondDeployment.ID, 1)

	timeline, err := repository.GetInvestigationTimeline(ctx, results[0].InvestigationID, InvestigationTimelineFilter{SourceType: "DEPLOYMENT"}, 10, 0)
	if err != nil {
		t.Fatalf("read deployment evidence timeline: %v", err)
	}
	if timeline.Total != 2 || len(timeline.Items) != 2 || timeline.Items[0].Evidence.Completeness != "COMPLETE" || timeline.Items[1].Evidence.Completeness != "COMPLETE" {
		t.Fatalf("deployment timeline = %+v, want both complete candidate facts", timeline)
	}
}

func TestIngestGrafanaAlertsRollsBackDeploymentCandidateEvidence(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	repository := NewPostgres(db)
	fixture := insertStoreFixture(t, ctx, db, "grafana-deployment-evidence-rollback")
	deploymentInput := fixture.deploymentInput("grafana-deployment-evidence-rollback")
	deploymentInput.SourceReference = "https://example.com/deployments/rollback"
	deployment, _, err := repository.CreateDeploymentEvent(ctx, deploymentInput)
	if err != nil {
		t.Fatalf("create deployment event: %v", err)
	}
	valid := fixtureAlertInput(fixture, "grafana-deployment-evidence-rollback-alert")
	valid.ProjectSlug = "grafana-deployment-evidence-rollback"
	invalid := fixtureAlertInput(fixture, "grafana-deployment-evidence-rollback-invalid")
	invalid.ProjectSlug = "missing-project"
	if _, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{valid, invalid}, "grafana-deployment-evidence-rollback-request", mustGrafanaEvidenceFilter(t)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("batch ingestion error = %v, want ErrNotFound", err)
	}
	var alertCount, evidenceCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM alerts WHERE fingerprint=$1`, valid.Fingerprint).Scan(&alertCount); err != nil {
		t.Fatalf("count rolled-back alert: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM evidence WHERE source_type='DEPLOYMENT' AND query_parameters->>'deployment_event_id'=$1`, deployment.ID).Scan(&evidenceCount); err != nil {
		t.Fatalf("count rolled-back deployment evidence: %v", err)
	}
	if alertCount != 0 || evidenceCount != 0 {
		t.Fatalf("rollback state: alerts=%d deployment evidence=%d, want both zero", alertCount, evidenceCount)
	}
}

func TestRemapGrafanaAlertPersistsDeploymentCandidateEvidence(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	repository := NewPostgres(db)
	fixture := insertStoreFixture(t, ctx, db, "grafana-remap-deployment-evidence")
	deploymentInput := fixture.deploymentInput("grafana-remap-deployment-evidence")
	deploymentInput.SourceReference = "https://example.com/deployments/remap"
	deployment, _, err := repository.CreateDeploymentEvent(ctx, deploymentInput)
	if err != nil {
		t.Fatalf("create deployment event: %v", err)
	}
	input := fixtureAlertInput(fixture, "grafana-remap-deployment-evidence-alert")
	input.ProjectSlug = "grafana-remap-deployment-evidence"
	input.ServiceSlug = "unmapped-service"
	filter := mustGrafanaEvidenceFilter(t)
	results, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "grafana-remap-deployment-evidence-request", filter)
	if err != nil {
		t.Fatalf("ingest unmapped alert: %v", err)
	}
	if len(results) != 1 || results[0].InvestigationID != "" {
		t.Fatalf("unmapped ingestion result = %+v, want no investigation", results)
	}
	remapped, err := repository.RemapGrafanaAlert(ctx, results[0].Alert.ID, results[0].Alert.EventVersion, fixture.serviceID, "prod", filter)
	if err != nil {
		t.Fatalf("remap Grafana alert: %v", err)
	}
	if remapped.InvestigationID == "" || remapped.DeploymentCount != 1 {
		t.Fatalf("remapped result = %+v, want investigation with one deployment candidate", remapped)
	}
	assertDeploymentEvidence(t, ctx, db, remapped.InvestigationID, deployment.ID, 1)
}

func assertDeploymentEvidence(t *testing.T, ctx context.Context, db *sql.DB, investigationID, deploymentID string, want int) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM evidence
		WHERE source_type='DEPLOYMENT' AND investigation_id=$1 AND query_parameters->>'deployment_event_id'=$2
	`, investigationID, deploymentID).Scan(&count); err != nil {
		t.Fatalf("count deployment candidate evidence: %v", err)
	}
	if count != want {
		t.Fatalf("deployment evidence count=%d, want %d", count, want)
	}
}

func mustGrafanaEvidenceFilter(t *testing.T, secrets ...string) *redact.Filter {
	t.Helper()
	filter, err := redact.NewFilter(secrets...)
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

func assertGrafanaEvidenceCount(t *testing.T, ctx context.Context, db *sql.DB, investigationID string, want int) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM evidence WHERE source_type='GRAFANA' AND investigation_id=$1`, investigationID).Scan(&count); err != nil {
		t.Fatalf("count Grafana evidence: %v", err)
	}
	if count != want {
		t.Fatalf("Grafana evidence count=%d, want %d", count, want)
	}
}

func TestPersistGrafanaAlertEvidenceSnapshotsAndOwnership(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	repository := NewPostgres(db)
	f := insertStoreFixture(t, ctx, db, "grafana-evidence")
	other := insertStoreFixture(t, ctx, db, "other-grafana-evidence")
	input := f.alertInput("grafana-evidence-alert")
	input.SourceReference = "https://example.com/alerts/1"
	a, _, err := repository.CreateAlert(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE incidents SET alert_id=$1 WHERE id=$2`, a.ID, f.incidentID); err != nil {
		t.Fatal(err)
	}
	// Matching project/service/environment is insufficient: the incident must link this alert.
	siblingInput := f.alertInput("grafana-evidence-sibling")
	siblingInput.Fingerprint = "another-alert"
	sibling, _, err := repository.CreateAlert(ctx, siblingInput)
	if err != nil {
		t.Fatal(err)
	}
	if sibling.ID == a.ID {
		t.Fatal("fixture must create a distinct unlinked alert")
	}
	var foreignToolCallID string
	if err := db.QueryRowContext(ctx, `INSERT INTO tool_calls (investigation_id,tool_name) VALUES ($1,'query_alert') RETURNING id::text`, other.investigationID).Scan(&foreignToolCallID); err != nil {
		t.Fatal(err)
	}
	filter, _ := redact.NewFilter()
	m := GrafanaAlertEvidenceContext{InvestigationID: f.investigationID, CollectedAt: f.startedAt.Add(time.Hour)}
	first, created, err := repository.PersistGrafanaAlertEvidence(ctx, a.ID, m, filter)
	if err != nil || !created {
		t.Fatalf("first: %+v %v %v", first, created, err)
	}
	m.CollectedAt = m.CollectedAt.Add(time.Minute)
	replay, created, err := repository.PersistGrafanaAlertEvidence(ctx, a.ID, m, filter)
	if err != nil || created || replay.ID != first.ID || first.CollectedAt == nil || replay.CollectedAt == nil || !replay.CollectedAt.Equal(*first.CollectedAt) {
		t.Fatalf("replay: %+v %v %v", replay, created, err)
	}
	// A status update creates a new immutable observation without counting as an independent source.
	end := f.startedAt.Add(5 * time.Minute)
	if _, err := db.ExecContext(ctx, `UPDATE alerts SET status='RESOLVED', ends_at=$2 WHERE id=$1`, a.ID, end); err != nil {
		t.Fatal(err)
	}
	resolved, created, err := repository.PersistGrafanaAlertEvidence(ctx, a.ID, m, filter)
	if err != nil || !created || resolved.ID == first.ID || resolved.IndependenceGroup != first.IndependenceGroup {
		t.Fatalf("resolved: %+v %v %v", resolved, created, err)
	}
	timeline, err := repository.GetInvestigationTimeline(ctx, f.investigationID, InvestigationTimelineFilter{SourceType: "GRAFANA"}, 10, 0)
	if err != nil || timeline.Total != 2 || len(timeline.Items) != 2 {
		t.Fatalf("timeline: %+v %v", timeline, err)
	}
	if !strings.Contains(string(timeline.Items[0].Evidence.ValueSummary), `"status": "FIRING"`) || !timeline.Items[0].Evidence.ObservedEnd.Equal(f.startedAt) || !timeline.Items[1].Evidence.ObservedEnd.Equal(end) {
		t.Fatalf("history: %+v", timeline.Items)
	}
	for _, tc := range []struct {
		name, id, investigation, tool string
		want                          error
	}{
		{name: "unlinked alert with same mapping", id: sibling.ID, investigation: f.investigationID, want: ErrInvalidInput},
		{name: "foreign tool", id: a.ID, investigation: f.investigationID, tool: foreignToolCallID, want: ErrInvalidInput},
		{name: "other investigation", id: a.ID, investigation: other.investigationID, want: ErrInvalidInput},
		{name: "unknown investigation", id: a.ID, investigation: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", want: ErrNotFound},
		{name: "unknown alert", id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", investigation: f.investigationID, want: ErrNotFound},
		{name: "invalid alert", id: "invalid", investigation: f.investigationID, want: ErrInvalidInput},
		{name: "unknown tool", id: a.ID, investigation: f.investigationID, tool: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", want: ErrInvalidInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			meta := m
			meta.InvestigationID = tc.investigation
			meta.ToolCallID = tc.tool
			_, _, err := repository.PersistGrafanaAlertEvidence(ctx, tc.id, meta, filter)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
		})
	}
	// Remapping an existing investigation must not silently accept different service/environment evidence.
	for _, query := range []string{
		`UPDATE investigations SET environment='staging' WHERE id=$1`,
		`UPDATE investigations SET environment='prod',service_id=NULL WHERE id=$1`,
	} {
		if _, err := db.ExecContext(ctx, query, f.investigationID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := repository.PersistGrafanaAlertEvidence(ctx, a.ID, m, filter); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("mapping mismatch=%v", err)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE investigations SET environment='prod', service_id=$2 WHERE id=$1`, f.investigationID, f.serviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE incidents SET environment='staging' WHERE id=$1`, f.incidentID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.PersistGrafanaAlertEvidence(ctx, a.ID, m, filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("incident mapping mismatch=%v", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM evidence`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("writes=%d %v", count, err)
	}
	// A downgrade may not erase or relabel immutable Grafana history.
	if err := goose.DownContext(ctx, db, "."); err == nil || !strings.Contains(err.Error(), "immutable GRAFANA") {
		t.Fatalf("rollback guard=%v", err)
	}
	var version int64
	version, err = goose.GetDBVersionContext(ctx, db)
	if err != nil || version != 9 {
		t.Fatalf("version=%d %v", version, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM evidence WHERE source_type='GRAFANA'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("preserved=%d %v", count, err)
	}
}
