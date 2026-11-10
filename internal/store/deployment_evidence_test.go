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

func deploymentEvidenceFixture() (DeploymentEvent, DeploymentEvidenceContext) {
	start := time.Date(2026, 11, 10, 8, 0, 0, 0, time.FixedZone("CST", 8*3600))
	end := start.Add(time.Minute)
	return DeploymentEvent{ID: "11111111-1111-4111-8111-111111111111", ProjectID: "22222222-2222-4222-8222-222222222222", ServiceID: "33333333-3333-4333-8333-333333333333", ReleaseID: "44444444-4444-4444-8444-444444444444", Environment: "prod", SourceSystem: "ci", Status: "SUCCEEDED", StartedAt: start, FinishedAt: &end, Version: "v1", CommitSHA: strings.Repeat("a", 40), SourceReference: "https://example.com/deploy/1", SourceTimezone: "Asia/Shanghai", SourceTimeText: "2026-11-10T08:00:00+08:00", EventVersion: 1, SourceConsistency: "MATCHED", SourceConflicts: json.RawMessage(`[]`)}, DeploymentEvidenceContext{InvestigationID: "55555555-5555-4555-8555-555555555555", CollectedAt: end.Add(time.Minute)}
}

func TestDeploymentEvidencePreservesFacts(t *testing.T) {
	event, meta := deploymentEvidenceFixture()
	filter, _ := redact.NewFilter()
	record, err := DeploymentEvidence(context.Background(), event, meta, filter)
	if err != nil {
		t.Fatal(err)
	}
	if record.SourceType != evidence.SourceDeployment || record.EntityType != "SERVICE" || record.EntityID == nil || *record.EntityID != event.ServiceID || record.IndependenceGroup != "deployment:"+event.ID || record.Completeness != evidence.CompletenessComplete {
		t.Fatalf("identity: %+v", record)
	}
	if !record.ObservedStart.Equal(event.StartedAt) || !record.ObservedEnd.Equal(*event.FinishedAt) || record.ObservedStart.Location() != time.UTC || record.SourceTimezone != event.SourceTimezone || record.SourceTimeText != event.SourceTimeText || record.FreshnessSeconds != nil {
		t.Fatalf("time: %+v", record)
	}
	if !strings.Contains(string(record.ValueSummary), `"event_version":1`) || !strings.Contains(string(record.ValueSummary), `"source_consistency":"MATCHED"`) {
		t.Fatalf("summary: %s", record.ValueSummary)
	}
	later := meta
	later.CollectedAt = later.CollectedAt.Add(time.Minute)
	replay, err := DeploymentEvidence(context.Background(), event, later, filter)
	if err != nil || replay.ContentHash != record.ContentHash {
		t.Fatalf("replay: %v %+v", err, replay)
	}
	event.EventVersion++
	updated, err := DeploymentEvidence(context.Background(), event, meta, filter)
	if err != nil || updated.ContentHash == record.ContentHash {
		t.Fatalf("updated: %v %+v", err, updated)
	}
}

func TestDeploymentEvidencePartialAndValidation(t *testing.T) {
	filter, _ := redact.NewFilter("private-secret")
	for _, tc := range []struct {
		name   string
		mutate func(*DeploymentEvent)
	}{
		{"unfinished", func(e *DeploymentEvent) { e.Status = "IN_PROGRESS"; e.FinishedAt = nil }},
		{"unverified", func(e *DeploymentEvent) { e.SourceConsistency = "UNVERIFIED" }},
		{"conflict", func(e *DeploymentEvent) {
			e.SourceConsistency = "SOURCE_CONFLICT"
			e.SourceConflicts = json.RawMessage(`["version"]`)
		}},
		{"no reference", func(e *DeploymentEvent) { e.SourceReference = "" }},
		{"unknown status", func(e *DeploymentEvent) { e.Status = "UNKNOWN" }},
		{"pending with finish", func(e *DeploymentEvent) { e.Status = "PENDING" }},
		{"in progress with finish", func(e *DeploymentEvent) { e.Status = "IN_PROGRESS" }},
		{"future finish", func(e *DeploymentEvent) { end := e.StartedAt.Add(time.Hour); e.FinishedAt = &end }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, m := deploymentEvidenceFixture()
			tc.mutate(&e)
			r, err := DeploymentEvidence(context.Background(), e, m, filter)
			if err != nil || r.Completeness != evidence.CompletenessPartial {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
	e, m := deploymentEvidenceFixture()
	e.Version = "private-secret"
	e.Metadata = json.RawMessage(`{"secret":"private-secret"}`)
	r, err := DeploymentEvidence(context.Background(), e, m, filter)
	if err != nil || strings.Contains(string(r.ValueSummary), "private-secret") {
		t.Fatalf("redaction: %s %v", r.ValueSummary, err)
	}
	e.ID = "invalid"
	if _, err = DeploymentEvidence(context.Background(), e, m, filter); !errors.Is(err, evidence.ErrInvalidInput) {
		t.Fatalf("invalid ID: %v", err)
	}
	e, m = deploymentEvidenceFixture()
	e.SourceConsistency = "MATCHED"
	e.SourceConflicts = json.RawMessage(`["version"]`)
	if _, err = DeploymentEvidence(context.Background(), e, m, filter); !errors.Is(err, evidence.ErrInvalidInput) {
		t.Fatalf("contradictory source facts: %v", err)
	}
	e, m = deploymentEvidenceFixture()
	end := e.StartedAt.Add(-time.Second)
	e.FinishedAt = &end
	if _, err = DeploymentEvidence(context.Background(), e, m, filter); !errors.Is(err, evidence.ErrInvalidInput) {
		t.Fatalf("invalid time range: %v", err)
	}
}
