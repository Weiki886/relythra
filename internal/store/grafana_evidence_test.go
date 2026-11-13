package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

func grafanaEvidenceFixture() (Alert, GrafanaAlertEvidenceContext) {
	start := time.Date(2026, 11, 10, 8, 0, 0, 0, time.FixedZone("CST", 8*3600))
	return Alert{ID: "11111111-1111-4111-8111-111111111111", ProjectID: "22222222-2222-4222-8222-222222222222", ServiceID: pointerTo("33333333-3333-4333-8333-333333333333"), Environment: pointerTo("prod"), Fingerprint: "latency", FingerprintVersion: "grafana-v1", EventVersion: 1, Status: "FIRING", Severity: "ERROR", Summary: "Latency elevated", StartsAt: start, SourceReference: "https://example.com/alert/1", SourceTimezone: "Asia/Shanghai", SourceTimeText: "2026-11-10T08:00:00+08:00"}, GrafanaAlertEvidenceContext{InvestigationID: "55555555-5555-4555-8555-555555555555", CollectedAt: start.Add(time.Hour)}
}

func TestGrafanaAlertEvidenceSnapshotsFactsAndGroupsTransitions(t *testing.T) {
	a, m := grafanaEvidenceFixture()
	filter, _ := redact.NewFilter("private-secret")
	a.Summary += " private-secret"
	a.SourceReference += "?token=private-secret"
	a.Labels = json.RawMessage(`{"ignored_label":"must-not-copy"}`)
	a.Annotations = a.Labels
	a.RedactedPayload = a.Labels
	a.IdempotencyKey = "must-not-copy"
	r, err := GrafanaAlertEvidence(context.Background(), a, m, filter)
	if err != nil {
		t.Fatal(err)
	}
	if r.SourceType != evidence.SourceGrafana || r.EntityType != "SERVICE" || r.EntityID == nil || *r.EntityID != *a.ServiceID || r.Completeness != evidence.CompletenessComplete || r.IndependenceGroup != "grafana:alert:"+a.ID {
		t.Fatalf("identity: %+v", r)
	}
	if !r.ObservedStart.Equal(a.StartsAt) || !r.ObservedEnd.Equal(a.StartsAt) || r.ObservedStart.Location() != time.UTC || r.SourceTimezone != a.SourceTimezone || r.SourceTimeText != a.SourceTimeText || r.FreshnessSeconds != nil {
		t.Fatalf("time: %+v", r)
	}
	var summary map[string]any
	if err := json.Unmarshal(r.ValueSummary, &summary); err != nil {
		t.Fatal(err)
	}
	if summary["alert_id"] != a.ID || summary["status"] != "FIRING" || summary["mapping_status"] != "MATCHED" || summary["event_version"] != float64(1) {
		t.Fatalf("summary: %s", r.ValueSummary)
	}
	body, _ := json.Marshal(r)
	for _, forbidden := range []string{"private-secret", "must-not-copy", "ignored_label", "idempotency_key", "redacted_payload"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("leaked %q: %s", forbidden, body)
		}
	}
	m.CollectedAt = m.CollectedAt.Add(time.Minute)
	replay, err := GrafanaAlertEvidence(context.Background(), a, m, filter)
	if err != nil || replay.ContentHash != r.ContentHash {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	a.Status = "RESOLVED"
	a.EndsAt = pointerTo(a.StartsAt.Add(5 * time.Minute))
	resolved, err := GrafanaAlertEvidence(context.Background(), a, m, filter)
	if err != nil || resolved.ContentHash == r.ContentHash || resolved.IndependenceGroup != r.IndependenceGroup || !resolved.ObservedEnd.Equal(*a.EndsAt) {
		t.Fatalf("resolved: %+v %v", resolved, err)
	}
	a.EventVersion++
	version, err := GrafanaAlertEvidence(context.Background(), a, m, filter)
	if err != nil || version.ContentHash == resolved.ContentHash {
		t.Fatalf("version: %+v %v", version, err)
	}
}

func TestGrafanaAlertEvidenceGaps(t *testing.T) {
	filter, _ := redact.NewFilter()
	for _, tc := range []struct {
		name   string
		mutate func(*Alert)
	}{
		{"no reference", func(a *Alert) { a.SourceReference = "" }},
		{"unmapped", func(a *Alert) { a.ServiceID = nil; a.Environment = nil }},
		{"missing environment", func(a *Alert) { a.Environment = nil }},
		{"resolved missing end", func(a *Alert) { a.Status = "RESOLVED" }},
		{"future start", func(a *Alert) { a.StartsAt = a.StartsAt.Add(2 * time.Hour) }},
		{"future end", func(a *Alert) { a.Status = "RESOLVED"; a.EndsAt = pointerTo(a.StartsAt.Add(2 * time.Hour)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, m := grafanaEvidenceFixture()
			tc.mutate(&a)
			r, err := GrafanaAlertEvidence(context.Background(), a, m, filter)
			if err != nil || r.Completeness != evidence.CompletenessPartial {
				t.Fatalf("gap: %+v %v", r, err)
			}
			if a.ServiceID == nil && (r.EntityType != "ALERT" || r.EntityID == nil || *r.EntityID != a.ID) {
				t.Fatalf("unmapped identity: %+v", r)
			}
		})
	}
}

func TestGrafanaAlertEvidenceRejectsInvalidInput(t *testing.T) {
	filter, _ := redact.NewFilter()
	for _, tc := range []struct {
		name   string
		mutate func(*Alert, *GrafanaAlertEvidenceContext)
	}{
		{"alert id", func(a *Alert, _ *GrafanaAlertEvidenceContext) { a.ID = "invalid" }},
		{"project id", func(a *Alert, _ *GrafanaAlertEvidenceContext) { a.ProjectID = "invalid" }},
		{"service id", func(a *Alert, _ *GrafanaAlertEvidenceContext) { a.ServiceID = pointerTo("invalid") }},
		{"empty environment", func(a *Alert, _ *GrafanaAlertEvidenceContext) { a.Environment = pointerTo(" ") }},
		{"status", func(a *Alert, _ *GrafanaAlertEvidenceContext) { a.Status = "UNKNOWN" }},
		{"fingerprint", func(a *Alert, _ *GrafanaAlertEvidenceContext) { a.Fingerprint = " " }},
		{"fingerprint version", func(a *Alert, _ *GrafanaAlertEvidenceContext) { a.FingerprintVersion = "" }},
		{"event version", func(a *Alert, _ *GrafanaAlertEvidenceContext) { a.EventVersion = 0 }},
		{"zero start", func(a *Alert, _ *GrafanaAlertEvidenceContext) { a.StartsAt = time.Time{} }},
		{"zero end", func(a *Alert, _ *GrafanaAlertEvidenceContext) {
			a.Status = "RESOLVED"
			a.EndsAt = pointerTo(time.Time{})
		}},
		{"reversed", func(a *Alert, _ *GrafanaAlertEvidenceContext) {
			a.Status = "RESOLVED"
			a.EndsAt = pointerTo(a.StartsAt.Add(-time.Minute))
		}},
		{"firing with end", func(a *Alert, _ *GrafanaAlertEvidenceContext) { a.EndsAt = pointerTo(a.StartsAt) }},
		{"investigation id", func(_ *Alert, m *GrafanaAlertEvidenceContext) { m.InvestigationID = "invalid" }},
		{"tool call id", func(_ *Alert, m *GrafanaAlertEvidenceContext) { m.ToolCallID = "invalid" }},
		{"zero collection", func(_ *Alert, m *GrafanaAlertEvidenceContext) { m.CollectedAt = time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, m := grafanaEvidenceFixture()
			tc.mutate(&a, &m)
			if _, err := GrafanaAlertEvidence(context.Background(), a, m, filter); !errors.Is(err, evidence.ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	a, m := grafanaEvidenceFixture()
	if _, err := GrafanaAlertEvidence(context.Background(), a, m, nil); !errors.Is(err, redact.ErrUnsafeOutput) {
		t.Fatalf("nil filter: %v", err)
	}
}
