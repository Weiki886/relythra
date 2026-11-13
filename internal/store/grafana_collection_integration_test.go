package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/security/redact"
)

func grafanaCollectionInput(project string) GrafanaAlertInput {
	return GrafanaAlertInput{
		ProjectSlug: project, ServiceSlug: "checkout-api", Environment: "prod",
		Fingerprint: "sha256:collection", FingerprintVersion: "sha256-v1",
		Status: "FIRING", Severity: "ERROR", Summary: "checkout latency is high",
		StartsAt:        time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC),
		SourceReference: "https://example.com/alerts/collection",
		SourceTimezone:  "+08:00", SourceTimeText: "2026-11-05T20:00:00+08:00",
		Labels: json.RawMessage(`{}`), Annotations: json.RawMessage(`{}`), RedactedPayload: json.RawMessage(`{}`),
	}
}

func TestGrafanaCollectionIngestionAndReplay(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	insertStoreFixture(t, ctx, db, "collection-replay")
	repository := NewPostgres(db)
	input := grafanaCollectionInput("collection-replay")
	first, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "collection-first", grafanaCollectionFilter(t))
	if err != nil {
		t.Fatal(err)
	}
	timeline, err := repository.GetInvestigationTimeline(ctx, first[0].InvestigationID, InvestigationTimelineFilter{SourceType: "GRAFANA"}, 10, 0)
	if err != nil || timeline.Total != 1 || len(timeline.Items) != 1 {
		t.Fatalf("initial timeline=%+v err=%v", timeline, err)
	}
	original := timeline.Items[0].Evidence
	if original.CollectedAt == nil || original.ToolCallID != nil || original.SourceTimezone != "+08:00" {
		t.Fatalf("snapshot=%+v", original)
	}
	if _, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "collection-replay", grafanaCollectionFilter(t)); err != nil {
		t.Fatal(err)
	}
	timeline, err = repository.GetInvestigationTimeline(ctx, first[0].InvestigationID, InvestigationTimelineFilter{SourceType: "GRAFANA"}, 10, 0)
	if err != nil || timeline.Total != 1 || len(timeline.Items) != 1 {
		t.Fatalf("replay timeline=%+v err=%v", timeline, err)
	}
	replay := timeline.Items[0].Evidence
	if replay.ID != original.ID || replay.CollectedAt == nil || !replay.CollectedAt.Equal(*original.CollectedAt) {
		t.Fatalf("replay=%+v original=%+v", replay, original)
	}
}

func TestGrafanaCollectionBatchPreservesTransitions(t *testing.T) {
	for _, knownEnd := range []bool{true, false} {
		name := "unknown-end"
		if knownEnd {
			name = "known-end"
		}
		t.Run(name, func(t *testing.T) {
			db := openStoreTestDB(t)
			ctx := context.Background()
			insertStoreFixture(t, ctx, db, "collection-transitions")
			repository := NewPostgres(db)
			firing := grafanaCollectionInput("collection-transitions")
			resolved := firing
			resolved.Status = "RESOLVED"
			end := firing.StartsAt.Add(5 * time.Minute)
			if knownEnd {
				resolved.EndsAt = &end
			}
			results, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{firing, resolved}, "collection-transitions", grafanaCollectionFilter(t))
			if err != nil {
				t.Fatal(err)
			}
			timeline, err := repository.GetInvestigationTimeline(ctx, results[0].InvestigationID, InvestigationTimelineFilter{SourceType: "GRAFANA"}, 10, 0)
			if err != nil || timeline.Total != 2 || len(timeline.Items) != 2 {
				t.Fatalf("timeline=%+v err=%v", timeline, err)
			}
			statuses := map[string]Evidence{}
			for _, item := range timeline.Items {
				var summary struct {
					Status   string `json:"status"`
					EndKnown bool   `json:"end_known"`
				}
				if err := json.Unmarshal(item.Evidence.ValueSummary, &summary); err != nil {
					t.Fatal(err)
				}
				statuses[summary.Status] = item.Evidence
				if summary.Status == "RESOLVED" && summary.EndKnown != knownEnd {
					t.Fatalf("end_known=%v", summary.EndKnown)
				}
			}
			a, b := statuses["FIRING"], statuses["RESOLVED"]
			if a.ID == "" || b.ID == "" || a.ID == b.ID || a.IndependenceGroup != b.IndependenceGroup {
				t.Fatalf("transitions=%+v", statuses)
			}
			if !a.ObservedEnd.Equal(firing.StartsAt) {
				t.Fatalf("firing end=%v", a.ObservedEnd)
			}
			if knownEnd && !b.ObservedEnd.Equal(end) {
				t.Fatalf("resolved end=%v", b.ObservedEnd)
			}
			if !knownEnd && (b.Completeness != "PARTIAL" || !b.ObservedEnd.Equal(firing.StartsAt)) {
				t.Fatalf("unknown end=%+v", b)
			}
		})
	}
}

func TestGrafanaCollectionMappingBoundaries(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "collection-mapping")
	repository := NewPostgres(db)
	unknown := grafanaCollectionInput("collection-mapping")
	unknown.ServiceSlug = "unknown-service"
	resolved := grafanaCollectionInput("collection-mapping")
	resolved.Fingerprint = "resolved-only"
	resolved.Status = "RESOLVED"
	results, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{unknown, resolved}, "collection-unmapped", grafanaCollectionFilter(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if result.InvestigationID != "" {
			t.Fatalf("unexpected investigation=%+v", result)
		}
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM evidence`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("before mapping evidence=%d err=%v", count, err)
	}
	result, err := repository.RemapGrafanaAlert(ctx, results[0].Alert.ID, results[0].Alert.EventVersion, fixture.serviceID, "prod", grafanaCollectionFilter(t))
	if err != nil {
		t.Fatal(err)
	}
	timeline, err := repository.GetInvestigationTimeline(ctx, result.InvestigationID, InvestigationTimelineFilter{SourceType: "GRAFANA"}, 10, 0)
	if err != nil || timeline.Total != 1 {
		t.Fatalf("mapped timeline=%+v err=%v", timeline, err)
	}
}

func TestGrafanaCollectionFailureRollsBack(t *testing.T) {
	for _, remapping := range []bool{false, true} {
		name := "ingestion"
		if remapping {
			name = "remapping"
		}
		t.Run(name, func(t *testing.T) {
			db := openStoreTestDB(t)
			ctx := context.Background()
			fixture := insertStoreFixture(t, ctx, db, "collection-rollback")
			repository := NewPostgres(db)
			input := grafanaCollectionInput("collection-rollback")
			var pending GrafanaAlertResult
			if remapping {
				input.ServiceSlug = "unknown-service"
				results, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "collection-pending", grafanaCollectionFilter(t))
				if err != nil {
					t.Fatal(err)
				}
				pending = results[0]
			}
			before := map[string]int{}
			for _, table := range []string{"alerts", "alert_deliveries", "incidents", "investigations", "investigation_transition_audits", "deployment_candidates", "evidence"} {
				var count int
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
					t.Fatal(err)
				}
				before[table] = count
			}
			// Fail on the second snapshot so ingestion must also roll back the first snapshot.
			if _, err := db.ExecContext(ctx, `CREATE FUNCTION reject_collection_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.value_summary->>'status'='RESOLVED' OR NEW.value_summary->>'event_version'='2' THEN RAISE EXCEPTION 'collection evidence unavailable'; END IF; RETURN NEW; END $$;
CREATE TRIGGER reject_collection BEFORE INSERT ON evidence FOR EACH ROW EXECUTE FUNCTION reject_collection_evidence()`); err != nil {
				t.Fatal(err)
			}
			if remapping {
				if _, err := repository.RemapGrafanaAlert(ctx, pending.Alert.ID, pending.Alert.EventVersion, fixture.serviceID, "prod", grafanaCollectionFilter(t)); err == nil || !strings.Contains(err.Error(), "collection evidence unavailable") {
					t.Fatalf("remap error=%v", err)
				}
				var version int64
				var mapped bool
				if err := db.QueryRowContext(ctx, `SELECT event_version,service_id IS NOT NULL FROM alerts WHERE id=$1`, pending.Alert.ID).Scan(&version, &mapped); err != nil || version != pending.Alert.EventVersion || mapped {
					t.Fatalf("mapping rollback version=%d mapped=%v err=%v", version, mapped, err)
				}
				if err := db.QueryRowContext(ctx, `SELECT service_id IS NOT NULL FROM incidents WHERE id=$1`, pending.IncidentID).Scan(&mapped); err != nil || mapped {
					t.Fatalf("incident mapping rollback mapped=%v err=%v", mapped, err)
				}
				var countForRollback int
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM investigations WHERE incident_id=$1`, pending.IncidentID).Scan(&countForRollback); err != nil || countForRollback != 0 {
					t.Fatalf("investigation rollback=%d err=%v", countForRollback, err)
				}
			} else {
				resolved := input
				resolved.Status = "RESOLVED"
				if _, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input, resolved}, "collection-rollback", grafanaCollectionFilter(t)); err == nil || !strings.Contains(err.Error(), "collection evidence unavailable") {
					t.Fatalf("ingestion error=%v", err)
				}
				for _, table := range []string{"alerts", "alert_deliveries"} {
					var count int
					if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil || count != 0 {
						t.Fatalf("%s rollback=%d err=%v", table, count, err)
					}
				}
			}
			for table, expected := range before {
				var count int
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil || count != expected {
					t.Fatalf("%s rollback count=%d want=%d err=%v", table, count, expected, err)
				}
			}
		})
	}
}

func grafanaCollectionFilter(t *testing.T) *redact.Filter {
	t.Helper()
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

func TestGrafanaCollectionRequiresFilter(t *testing.T) {
	// Validate fail-closed behavior before opening any database connection.
	repository := NewPostgres(nil)
	if _, err := repository.IngestGrafanaAlerts(context.Background(), []GrafanaAlertInput{grafanaCollectionInput("filter")}, "filter-request", nil); !errors.Is(err, redact.ErrUnsafeOutput) {
		t.Fatalf("ingestion error=%v", err)
	}
	if _, err := repository.RemapGrafanaAlert(context.Background(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 1, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "prod", nil); !errors.Is(err, redact.ErrUnsafeOutput) {
		t.Fatalf("remap error=%v", err)
	}
}

func TestGrafanaCollectionUsesConfiguredFilter(t *testing.T) {
	for _, remapping := range []bool{false, true} {
		name := "ingestion"
		if remapping {
			name = "remapping"
		}
		t.Run(name, func(t *testing.T) {
			db := openStoreTestDB(t)
			ctx := context.Background()
			fixture := insertStoreFixture(t, ctx, db, "collection-filter")
			repository := NewPostgres(db)
			const canary = "deployment-access-canary-value"
			filter, err := redact.NewFilter(canary)
			if err != nil {
				t.Fatal(err)
			}
			input := grafanaCollectionInput("collection-filter")
			input.Summary = "latency increased with " + canary
			if remapping {
				input.ServiceSlug = "unknown-service"
			}
			results, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "collection-filter", filter)
			if err != nil {
				t.Fatal(err)
			}
			result := results[0]
			if remapping {
				result, err = repository.RemapGrafanaAlert(ctx, result.Alert.ID, result.Alert.EventVersion, fixture.serviceID, "prod", filter)
				if err != nil {
					t.Fatal(err)
				}
			}
			timeline, err := repository.GetInvestigationTimeline(ctx, result.InvestigationID, InvestigationTimelineFilter{SourceType: "GRAFANA"}, 10, 0)
			if err != nil || timeline.Total != 1 || len(timeline.Items) != 1 {
				t.Fatalf("timeline=%+v err=%v", timeline, err)
			}
			summary := string(timeline.Items[0].Evidence.ValueSummary)
			if strings.Contains(summary, canary) || !strings.Contains(summary, "[REDACTED]") {
				t.Fatalf("unsafe summary=%s", summary)
			}
		})
	}
}

func TestGrafanaCollectionRejectsChangedInvestigationMapping(t *testing.T) {
	for _, remapping := range []bool{false, true} {
		name := "ingestion"
		if remapping {
			name = "remapping"
		}
		t.Run(name, func(t *testing.T) {
			db := openStoreTestDB(t)
			ctx := context.Background()
			fixture := insertStoreFixture(t, ctx, db, "collection-ownership")
			repository := NewPostgres(db)
			input := grafanaCollectionInput("collection-ownership")
			filter := grafanaCollectionFilter(t)
			results, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "collection-initial", filter)
			if err != nil {
				t.Fatal(err)
			}
			original := results[0]
			if remapping {
				_, err = repository.RemapGrafanaAlert(ctx, original.Alert.ID, original.Alert.EventVersion, fixture.serviceID, "staging", filter)
			} else {
				input.Environment = "staging"
				_, err = repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "collection-changed", filter)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("ownership error=%v", err)
			}
			var alertEnv, incidentEnv, investigationEnv string
			var version int64
			if err := db.QueryRowContext(ctx, `SELECT a.environment, inc.environment, i.environment, a.event_version FROM alerts a JOIN incidents inc ON inc.alert_id=a.id JOIN investigations i ON i.incident_id=inc.id WHERE a.id=$1`, original.Alert.ID).Scan(&alertEnv, &incidentEnv, &investigationEnv, &version); err != nil {
				t.Fatal(err)
			}
			if alertEnv != "prod" || incidentEnv != "prod" || investigationEnv != "prod" || version != original.Alert.EventVersion {
				t.Fatalf("mapping rollback=%s/%s/%s version=%d", alertEnv, incidentEnv, investigationEnv, version)
			}
			var deliveries int
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM alert_deliveries WHERE alert_id=$1`, original.Alert.ID).Scan(&deliveries); err != nil || deliveries != 1 {
				t.Fatalf("deliveries=%d err=%v", deliveries, err)
			}
			timeline, err := repository.GetInvestigationTimeline(ctx, original.InvestigationID, InvestigationTimelineFilter{SourceType: "GRAFANA"}, 10, 0)
			if err != nil || timeline.Total != 1 {
				t.Fatalf("timeline=%+v err=%v", timeline, err)
			}
		})
	}
}

func TestGrafanaCollectionResolvedRemapping(t *testing.T) {
	for _, withInvestigation := range []bool{false, true} {
		name := "resolved-only"
		if withInvestigation {
			name = "existing-investigation"
		}
		t.Run(name, func(t *testing.T) {
			db := openStoreTestDB(t)
			ctx := context.Background()
			fixture := insertStoreFixture(t, ctx, db, "collection-resolved-remap")
			repository := NewPostgres(db)
			input := grafanaCollectionInput("collection-resolved-remap")
			filter := grafanaCollectionFilter(t)
			if withInvestigation {
				if _, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "collection-firing", filter); err != nil {
					t.Fatal(err)
				}
			}
			input.Status = "RESOLVED"
			results, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "collection-resolved", filter)
			if err != nil {
				t.Fatal(err)
			}
			original := results[0]
			if withInvestigation {
				if _, err := repository.RemapGrafanaAlert(ctx, original.Alert.ID, original.Alert.EventVersion, fixture.serviceID, "staging", filter); !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("resolved ownership error=%v", err)
				}
			}
			mapped, err := repository.RemapGrafanaAlert(ctx, original.Alert.ID, original.Alert.EventVersion, fixture.serviceID, "prod", filter)
			if err != nil {
				t.Fatal(err)
			}
			if withInvestigation {
				if mapped.InvestigationID != original.InvestigationID {
					t.Fatalf("resolved mapping investigation=%q want=%q", mapped.InvestigationID, original.InvestigationID)
				}
				timeline, err := repository.GetInvestigationTimeline(ctx, original.InvestigationID, InvestigationTimelineFilter{SourceType: "GRAFANA"}, 10, 0)
				if err != nil || timeline.Total != 3 {
					t.Fatalf("resolved remapping timeline=%+v err=%v", timeline, err)
				}
			} else {
				var investigations int
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM investigations WHERE incident_id=$1`, original.IncidentID).Scan(&investigations); err != nil || investigations != 0 || mapped.InvestigationID != "" {
					t.Fatalf("resolved-only investigations=%d result=%+v err=%v", investigations, mapped, err)
				}
				var evidenceCount int
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM evidence`).Scan(&evidenceCount); err != nil || evidenceCount != 0 {
					t.Fatalf("resolved-only evidence=%d err=%v", evidenceCount, err)
				}
			}
		})
	}
}
