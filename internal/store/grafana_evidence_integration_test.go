package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/pressly/goose/v3"
)

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
