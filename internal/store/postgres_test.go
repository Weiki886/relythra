package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/migrations"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestCreateDeploymentEventIsIdempotentUnderConcurrency(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "deploy-idempotency")
	repository := NewPostgres(db)
	input := fixture.deploymentInput("deploy-concurrent-1")

	const writers = 8
	type result struct {
		event   DeploymentEvent
		created bool
		err     error
	}
	results := make(chan result, writers)
	var group sync.WaitGroup
	for range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			event, created, err := repository.CreateDeploymentEvent(ctx, input)
			results <- result{event: event, created: created, err: err}
		}()
	}
	group.Wait()
	close(results)

	var stableID string
	var createdCount int
	for result := range results {
		if result.err != nil {
			t.Fatalf("create deployment event: %v", result.err)
		}
		if stableID == "" {
			stableID = result.event.ID
		}
		if result.event.ID != stableID {
			t.Errorf("stable deployment ID changed: got %s, want %s", result.event.ID, stableID)
		}
		if result.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("created count = %d, want 1", createdCount)
	}

	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM deployment_events WHERE idempotency_key = $1
	`, input.IdempotencyKey).Scan(&count); err != nil {
		t.Fatalf("count deployment events: %v", err)
	}
	if count != 1 {
		t.Fatalf("deployment event count = %d, want 1", count)
	}
}

func TestClaimDeploymentWebhookSignatureIsAtomicAndRejectsReplay(t *testing.T) {
	db := openStoreTestDB(t)
	repository := NewPostgres(db)
	digest := make([]byte, 32)
	digest[0] = 42
	expiresAt := time.Now().UTC().Add(5 * time.Minute)

	const writers = 8
	results := make(chan bool, writers)
	var group sync.WaitGroup
	for range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			claimed, err := repository.ClaimDeploymentWebhookSignature(context.Background(), digest, expiresAt)
			if err != nil {
				t.Errorf("claim signature: %v", err)
				return
			}
			results <- claimed
		}()
	}
	group.Wait()
	close(results)

	claimedCount := 0
	for claimed := range results {
		if claimed {
			claimedCount++
		}
	}
	if claimedCount != 1 {
		t.Fatalf("successful claims = %d, want exactly 1", claimedCount)
	}
	claimed, err := repository.ClaimDeploymentWebhookSignature(context.Background(), digest, expiresAt)
	if err != nil || claimed {
		t.Fatalf("replayed claim = %v, %v; want false, nil", claimed, err)
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO deployment_webhook_signatures (signature_digest, expires_at)
		VALUES ($1, now() - interval '2 minutes')
	`, bytesOf(43)); err != nil {
		t.Fatalf("insert expired signature fixture: %v", err)
	}
	if _, err := repository.ClaimDeploymentWebhookSignature(context.Background(), bytesOf(44), expiresAt); err != nil {
		t.Fatalf("claim after expiry cleanup: %v", err)
	}
	var expiredCount int
	if err := db.QueryRowContext(context.Background(), `
		SELECT count(*) FROM deployment_webhook_signatures WHERE signature_digest = $1
	`, bytesOf(43)).Scan(&expiredCount); err != nil {
		t.Fatalf("check expired signature cleanup: %v", err)
	}
	if expiredCount != 0 {
		t.Fatalf("expired signature count = %d, want 0", expiredCount)
	}
}

func bytesOf(value byte) []byte {
	result := make([]byte, 32)
	result[0] = value
	return result
}

func TestCreateDeploymentEventRejectsIdempotencyKeyReuseWithDifferentFacts(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "deploy-idempotency-content")
	repository := NewPostgres(db)
	input := fixture.deploymentInput("external-deployment-100")
	input.Status = "PENDING"
	input.FinishedAt = nil
	if _, created, err := repository.CreateDeploymentEvent(ctx, input); err != nil || !created {
		t.Fatalf("create first deployment: created=%v err=%v", created, err)
	}
	input.CommitSHA = strings.Repeat("d", 40)
	if _, _, err := repository.CreateDeploymentEvent(ctx, input); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused idempotency key error = %v, want ErrConflict", err)
	}
}

func TestTransitionDeploymentEventIsVersionedAndAudited(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "deploy-transition")
	repository := NewPostgres(db)
	input := fixture.deploymentInput("external-deployment-101")
	input.Status = "PENDING"
	input.FinishedAt = nil
	event, created, err := repository.CreateDeploymentEvent(ctx, input)
	if err != nil || !created {
		t.Fatalf("create deployment: created=%v err=%v", created, err)
	}
	if event.EventVersion != 1 {
		t.Fatalf("initial event version = %d, want 1", event.EventVersion)
	}
	updated, err := repository.UpdateDeploymentEvent(ctx, event.ID, UpdateDeploymentEventInput{
		ExpectedVersion: 1,
		Actor:           "ci:checkout",
		RequestID:       "req-deploy-101",
		Reason:          "deployment started",
		Status:          "IN_PROGRESS",
	})
	if err != nil {
		t.Fatalf("transition to IN_PROGRESS: %v", err)
	}
	if updated.Status != "IN_PROGRESS" || updated.EventVersion != 2 {
		t.Fatalf("updated event status/version = %s/%d", updated.Status, updated.EventVersion)
	}
	if _, err := repository.UpdateDeploymentEvent(ctx, event.ID, UpdateDeploymentEventInput{
		ExpectedVersion: 1,
		Actor:           "ci:checkout",
		RequestID:       "req-deploy-101-stale",
		Reason:          "stale duplicate",
		Status:          "SUCCEEDED",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale transition error = %v, want ErrConflict", err)
	}
	if _, err := repository.UpdateDeploymentEvent(ctx, event.ID, UpdateDeploymentEventInput{
		ExpectedVersion: 2,
		Actor:           "ci:checkout",
		RequestID:       "req-deploy-101-invalid",
		Reason:          "invalid terminal jump",
		Status:          "ROLLED_BACK",
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid transition error = %v, want ErrInvalidTransition", err)
	}
	corrected, err := repository.UpdateDeploymentEvent(ctx, event.ID, UpdateDeploymentEventInput{
		ExpectedVersion: 2,
		Actor:           "operator:local-admin",
		RequestID:       "req-deploy-101-correction",
		Reason:          "deployment record corrected from CI run metadata",
		CommitSHA:       strings.Repeat("d", 40),
		SourceReference: "https://ci.example.test/runs/101",
	})
	if err != nil {
		t.Fatalf("correct deployment facts: %v", err)
	}
	if corrected.EventVersion != 3 || corrected.SourceConsistency != "SOURCE_CONFLICT" ||
		!strings.Contains(string(corrected.SourceConflicts), "commit_sha") {
		t.Fatalf("corrected deployment consistency = %d/%s/%s", corrected.EventVersion, corrected.SourceConsistency, corrected.SourceConflicts)
	}
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM deployment_event_updates WHERE deployment_event_id = $1
	`, event.ID).Scan(&count); err != nil {
		t.Fatalf("count deployment event updates: %v", err)
	}
	if count != 3 {
		t.Fatalf("deployment update audit count = %d, want create, transition, and correction", count)
	}
}

func TestFindDeploymentCandidatesReturnsAllOverlappingDeployments(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "deploy-candidates")
	repository := NewPostgres(db)
	starts := []time.Time{
		fixture.startedAt.Add(-5 * time.Minute),
		fixture.startedAt.Add(5 * time.Minute),
		fixture.startedAt.Add(time.Hour),
	}
	for index, key := range []string{"candidate-window-1", "candidate-window-2", "candidate-outside"} {
		input := fixture.deploymentInput(key)
		input.StartedAt = starts[index]
		input.FinishedAt = pointerTo(input.StartedAt.Add(10 * time.Minute))
		input.Status = "SUCCEEDED"
		if _, _, err := repository.CreateDeploymentEvent(ctx, input); err != nil {
			t.Fatalf("create %s: %v", key, err)
		}
	}
	candidates, err := repository.FindDeploymentCandidates(ctx, DeploymentCandidateQuery{
		ProjectID:   fixture.projectID,
		ServiceID:   fixture.serviceID,
		Environment: "prod",
		Start:       fixture.startedAt.Add(-5 * time.Minute),
		End:         fixture.startedAt.Add(30 * time.Minute),
		Limit:       10,
	})
	if err != nil {
		t.Fatalf("find deployment candidates: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want both overlapping deployments", len(candidates))
	}
}

func TestCreateAlertReusesFingerprintWindow(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "alert-idempotency")
	repository := NewPostgres(db)

	firstInput := fixture.alertInput("alert-delivery-1")
	first, created, err := repository.CreateAlert(ctx, firstInput)
	if err != nil {
		t.Fatalf("create first alert: %v", err)
	}
	if !created {
		t.Fatal("first alert was not reported as created")
	}

	secondInput := firstInput
	secondInput.IdempotencyKey = "alert-delivery-2"
	second, created, err := repository.CreateAlert(ctx, secondInput)
	if err != nil {
		t.Fatalf("create duplicate alert window: %v", err)
	}
	if created {
		t.Fatal("duplicate alert window was reported as created")
	}
	if second.ID != first.ID {
		t.Fatalf("duplicate alert ID = %s, want %s", second.ID, first.ID)
	}

	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM alerts WHERE project_id = $1
	`, fixture.projectID).Scan(&count); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	if count != 1 {
		t.Fatalf("alert count = %d, want 1", count)
	}
}

func TestIngestGrafanaAlertCreatesIncidentAndReusesItOnDuplicate(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "grafana-ingestion")
	repository := NewPostgres(db)
	input := GrafanaAlertInput{
		ProjectSlug: "grafana-ingestion", ServiceSlug: "checkout-api", Environment: "prod",
		Fingerprint: "sha256:fingerprint", FingerprintVersion: "sha256-v1", Status: "FIRING",
		Severity: "ERROR", Summary: "Checkout latency is high", StartsAt: fixture.startedAt,
		SourceTimezone: "+08:00", SourceTimeText: "2026-11-05T20:00:00+08:00",
		Labels:          json.RawMessage(`{"project":"grafana-ingestion","service":"checkout-api","env":"prod"}`),
		Annotations:     json.RawMessage(`{"summary":"Checkout latency is high"}`),
		RedactedPayload: json.RawMessage(`{"status":"firing","alerts":[]}`),
	}
	first, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "grafana-request-1")
	if err != nil {
		t.Fatalf("ingest firing alert: %v", err)
	}
	if len(first) != 1 || !first[0].Created || first[0].MatchState != "MATCHED" || first[0].InvestigationID == "" {
		t.Fatalf("first ingestion = %+v", first)
	}
	if first[0].Alert.SourceTimezone != input.SourceTimezone || first[0].Alert.SourceTimeText != input.SourceTimeText {
		t.Fatalf("persisted source timestamp = %q / %q", first[0].Alert.SourceTimezone, first[0].Alert.SourceTimeText)
	}
	second, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "grafana-request-2")
	if err != nil {
		t.Fatalf("ingest duplicate alert: %v", err)
	}
	if len(second) != 1 || second[0].Created || !second[0].Duplicate ||
		second[0].Alert.ID != first[0].Alert.ID || second[0].IncidentID != first[0].IncidentID ||
		second[0].InvestigationID != first[0].InvestigationID {
		t.Fatalf("duplicate ingestion = %+v; first = %+v", second, first)
	}

	resolvedAt := fixture.startedAt.Add(5 * time.Minute)
	input.Status = "RESOLVED"
	input.EndsAt = &resolvedAt
	resolved, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "grafana-request-3")
	if err != nil {
		t.Fatalf("ingest resolved alert: %v", err)
	}
	if resolved[0].Alert.Status != "RESOLVED" || resolved[0].Alert.EndsAt == nil || resolved[0].InvestigationID != first[0].InvestigationID {
		t.Fatalf("resolved ingestion = %+v", resolved[0])
	}
	var deliveryCount, investigationCount, deploymentCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM alert_deliveries WHERE alert_id = $1`, first[0].Alert.ID).Scan(&deliveryCount); err != nil {
		t.Fatalf("count alert deliveries: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM investigations WHERE incident_id = $1`, first[0].IncidentID).Scan(&investigationCount); err != nil {
		t.Fatalf("count investigations: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE id = $1 AND status = 'RESOLVED' AND ended_at = $2`, first[0].IncidentID, resolvedAt).Scan(&deploymentCount); err != nil {
		t.Fatalf("check resolved incident: %v", err)
	}
	if deliveryCount != 3 || investigationCount != 1 || deploymentCount != 1 {
		t.Fatalf("delivery/investigation/resolved incident counts = %d/%d/%d", deliveryCount, investigationCount, deploymentCount)
	}
}

func TestIngestGrafanaAlertAllowsRepeatedFingerprintWithinOneRequest(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "grafana-batch-duplicate")
	repository := NewPostgres(db)
	input := fixtureAlertInput(fixture, "same-envelope-fingerprint")
	input.ProjectSlug = "grafana-batch-duplicate"

	results, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input, input}, "grafana-shared-request")
	if err != nil {
		t.Fatalf("ingest repeated fingerprint in one request: %v", err)
	}
	if len(results) != 2 || results[0].Alert.ID != results[1].Alert.ID || results[1].Duplicate != true {
		t.Fatalf("batch results = %+v", results)
	}
	var deliveryCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM alert_deliveries WHERE alert_id = $1 AND request_id = $2`, results[0].Alert.ID, "grafana-shared-request").Scan(&deliveryCount); err != nil {
		t.Fatalf("count deliveries: %v", err)
	}
	if deliveryCount != 2 {
		t.Fatalf("delivery count = %d, want each alert entry retained", deliveryCount)
	}
}

func TestIngestGrafanaAlertLeavesUnknownServiceForMappingAndRollsBackWholeBatch(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "grafana-unmapped")
	repository := NewPostgres(db)
	input := GrafanaAlertInput{
		ProjectSlug: "grafana-unmapped", ServiceSlug: "unknown-service", Environment: "Prod",
		Fingerprint: "grafana-unmapped-fingerprint", FingerprintVersion: "sha256-v1", Status: "FIRING",
		Severity: "WARNING", Summary: "Unmapped alert", StartsAt: fixture.startedAt,
		Labels: json.RawMessage(`{"alertname":"Unmapped"}`), Annotations: json.RawMessage(`{"summary":"Unmapped alert"}`),
		RedactedPayload: json.RawMessage(`{"alerts":[]}`),
	}
	results, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "unmapped-request-1")
	if err != nil {
		t.Fatalf("ingest unmapped alert: %v", err)
	}
	if len(results) != 1 || results[0].MatchState != "NEEDS_MAPPING" || results[0].InvestigationID != "" {
		t.Fatalf("unmapped ingestion = %+v", results)
	}
	var incidentService sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT service_id::text FROM incidents WHERE id = $1`, results[0].IncidentID).Scan(&incidentService); err != nil {
		t.Fatalf("read pending mapping incident: %v", err)
	}
	if incidentService.Valid {
		t.Fatalf("pending incident has guessed service %q", incidentService.String)
	}

	valid := fixtureAlertInput(fixture, "batch-rollback-valid")
	invalid := valid
	invalid.ProjectSlug = "project-that-does-not-exist"
	if _, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{valid, invalid}, "batch-rollback-request"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("batch with unresolved project error = %v, want ErrNotFound", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM alerts WHERE fingerprint = $1`, valid.Fingerprint).Scan(&count); err != nil {
		t.Fatalf("check batch rollback: %v", err)
	}
	if count != 0 {
		t.Fatalf("alerts from failed batch = %d, want 0", count)
	}
}

func fixtureAlertInput(fixture storeFixture, fingerprint string) GrafanaAlertInput {
	return GrafanaAlertInput{
		ProjectSlug: "grafana-unmapped", ServiceSlug: "checkout-api", Environment: "prod",
		Fingerprint: fingerprint, FingerprintVersion: "sha256-v1", Status: "FIRING", Severity: "ERROR",
		Summary: "Checkout alert", StartsAt: fixture.startedAt, Labels: json.RawMessage(`{"alertname":"Checkout"}`),
		Annotations: json.RawMessage(`{"summary":"Checkout alert"}`), RedactedPayload: json.RawMessage(`{"alerts":[]}`),
	}
}

func TestIngestGrafanaAlertDeduplicatesConcurrentFingerprints(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "grafana-concurrent")
	repository := NewPostgres(db)
	input := fixtureAlertInput(fixture, "concurrent-fingerprint")
	input.ProjectSlug = "grafana-concurrent"

	const writers = 8
	var group sync.WaitGroup
	errorsChannel := make(chan error, writers)
	ids := make(chan string, writers)
	for index := range writers {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			results, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, fmt.Sprintf("concurrent-request-%d", index))
			if err != nil {
				errorsChannel <- err
				return
			}
			ids <- results[0].Alert.ID
		}(index)
	}
	group.Wait()
	close(errorsChannel)
	close(ids)
	for err := range errorsChannel {
		t.Errorf("concurrent ingestion: %v", err)
	}
	var stableID string
	for id := range ids {
		if stableID == "" {
			stableID = id
		}
		if id != stableID {
			t.Errorf("concurrent alert ID = %s, want %s", id, stableID)
		}
	}
	var alertCount, incidentCount, investigationCount, deliveryCount int
	for query, target := range map[string]*int{
		`SELECT count(*) FROM alerts WHERE fingerprint = 'concurrent-fingerprint'`:                               &alertCount,
		`SELECT count(*) FROM incidents WHERE alert_id = $1`:                                                     &incidentCount,
		`SELECT count(*) FROM investigations WHERE incident_id = (SELECT id FROM incidents WHERE alert_id = $1)`: &investigationCount,
		`SELECT count(*) FROM alert_deliveries WHERE alert_id = $1`:                                              &deliveryCount,
	} {
		var err error
		if strings.Contains(query, "$1") {
			err = db.QueryRowContext(ctx, query, stableID).Scan(target)
		} else {
			err = db.QueryRowContext(ctx, query).Scan(target)
		}
		if err != nil {
			t.Fatalf("count concurrent ingestion rows: %v", err)
		}
	}
	if alertCount != 1 || incidentCount != 1 || investigationCount != 1 || deliveryCount != writers {
		t.Fatalf("concurrent row counts alert/incident/investigation/delivery = %d/%d/%d/%d", alertCount, incidentCount, investigationCount, deliveryCount)
	}
}

func TestRemapGrafanaAlertUsesVersionAndCreatesInvestigation(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "grafana-remap")
	repository := NewPostgres(db)
	input := fixtureAlertInput(fixture, "remap-fingerprint")
	input.ProjectSlug = "grafana-remap"
	input.ServiceSlug = "missing-service"
	input.Environment = "bad Env"
	created, err := repository.IngestGrafanaAlerts(ctx, []GrafanaAlertInput{input}, "remap-request-1")
	if err != nil {
		t.Fatalf("ingest unmapped alert: %v", err)
	}
	result, err := repository.RemapGrafanaAlert(ctx, created[0].Alert.ID, created[0].Alert.EventVersion, fixture.serviceID, "prod")
	if err != nil {
		t.Fatalf("remap Grafana alert: %v", err)
	}
	if result.MatchState != "MATCHED" || result.InvestigationID == "" || result.Alert.EventVersion != 2 {
		t.Fatalf("remapped alert result = %+v", result)
	}
	if _, err := repository.RemapGrafanaAlert(ctx, result.Alert.ID, 1, fixture.serviceID, "prod"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale remap error = %v, want ErrConflict", err)
	}
}

func TestCreateEventRejectsInvalidTimeWindows(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "invalid-time")
	repository := NewPostgres(db)

	invalidDeployment := fixture.deploymentInput("invalid-deployment-time")
	invalidDeployment.StartedAt = time.Time{}
	if _, _, err := repository.CreateDeploymentEvent(ctx, invalidDeployment); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing deployment start error = %v, want ErrInvalidInput", err)
	}

	invertedDeployment := fixture.deploymentInput("inverted-deployment-time")
	invertedDeployment.FinishedAt = pointerTo(invertedDeployment.StartedAt.Add(-time.Second))
	if _, _, err := repository.CreateDeploymentEvent(ctx, invertedDeployment); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("inverted deployment time error = %v, want ErrInvalidInput", err)
	}

	invalidAlert := fixture.alertInput("invalid-alert-time")
	invalidAlert.StartsAt = time.Time{}
	if _, _, err := repository.CreateAlert(ctx, invalidAlert); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing alert start error = %v, want ErrInvalidInput", err)
	}

	invertedAlert := fixture.alertInput("inverted-alert-time")
	invertedAlert.EndsAt = pointerTo(invertedAlert.StartsAt.Add(-time.Second))
	if _, _, err := repository.CreateAlert(ctx, invertedAlert); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("inverted alert time error = %v, want ErrInvalidInput", err)
	}
}

func TestEvidenceCannotReferenceToolCallFromAnotherInvestigation(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	first := insertStoreFixture(t, ctx, db, "evidence-owner")
	second := insertStoreFixture(t, ctx, db, "tool-call-owner")

	var foreignToolCallID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO tool_calls (investigation_id, tool_name)
		VALUES ($1, 'query_metric_template')
		RETURNING id::text
	`, second.investigationID).Scan(&foreignToolCallID); err != nil {
		t.Fatalf("insert foreign tool call: %v", err)
	}

	_, err := db.ExecContext(ctx, `
		INSERT INTO evidence (
			investigation_id, tool_call_id, source_type, entity_type, entity_id,
			observed_start, observed_end, value_summary, completeness,
			independence_group, content_hash
		) VALUES (
			$1, $2, 'PROMETHEUS', 'service', $3, $4::timestamptz,
			$4::timestamptz + interval '5 minutes', '{"p95_ms":420}'::jsonb,
			'COMPLETE', 'metrics', $5
		)
	`, first.investigationID, foreignToolCallID, first.serviceID, first.startedAt,
		strings.Repeat("d", 64))
	if err == nil {
		t.Fatal("cross-investigation tool call was accepted")
	}
}

func TestDeploymentCandidateCannotLinkAcrossProjects(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	first := insertStoreFixture(t, ctx, db, "candidate-incident")
	second := insertStoreFixture(t, ctx, db, "candidate-deployment")
	repository := NewPostgres(db)

	sameProjectDeployment, _, err := repository.CreateDeploymentEvent(
		ctx,
		first.deploymentInput("same-project-candidate"),
	)
	if err != nil {
		t.Fatalf("create same-project deployment event: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO deployment_candidates (
			project_id, incident_id, deployment_event_id, match_status, match_reason
		) VALUES ($1, $2, $3, 'MATCHED', 'same-project candidate')
	`, first.projectID, first.incidentID, sameProjectDeployment.ID); err != nil {
		t.Fatalf("link same-project deployment candidate: %v", err)
	}

	deployment, _, err := repository.CreateDeploymentEvent(
		ctx,
		second.deploymentInput("cross-project-candidate"),
	)
	if err != nil {
		t.Fatalf("create deployment event: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO deployment_candidates (
			project_id, incident_id, deployment_event_id, match_status, match_reason
		) VALUES ($1, $2, $3, 'MATCHED', 'invalid cross-project link')
	`, first.projectID, first.incidentID, deployment.ID)
	if err == nil {
		t.Fatal("cross-project deployment candidate was accepted")
	}
}

func TestTransitionInvestigationRejectsStaleAndInvalidChanges(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "transition")
	repository := NewPostgres(db)

	matched, err := repository.TransitionInvestigation(
		ctx,
		fixture.investigationID,
		1,
		domain.InvestigationMatched,
	)
	if err != nil {
		t.Fatalf("transition to MATCHED: %v", err)
	}
	if matched.Status != domain.InvestigationMatched || matched.Version != 2 {
		t.Fatalf("unexpected MATCHED result: status=%s version=%d", matched.Status, matched.Version)
	}

	if _, err := repository.TransitionInvestigation(
		ctx,
		fixture.investigationID,
		2,
		domain.InvestigationCompleted,
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid transition error = %v, want ErrInvalidTransition", err)
	}
	if _, err := repository.TransitionInvestigation(
		ctx,
		fixture.investigationID,
		1,
		domain.InvestigationCollecting,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale transition error = %v, want ErrConflict", err)
	}
	if _, err := repository.TransitionInvestigation(
		ctx,
		"00000000-0000-4000-8000-000000000000",
		1,
		domain.InvestigationMatched,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing investigation error = %v, want ErrNotFound", err)
	}

	for expectedVersion, status := range []domain.InvestigationStatus{
		domain.InvestigationCollecting,
		domain.InvestigationHypothesizing,
		domain.InvestigationVerifying,
		domain.InvestigationCompleted,
	} {
		current, err := repository.TransitionInvestigation(
			ctx,
			fixture.investigationID,
			int64(expectedVersion+2),
			status,
		)
		if err != nil {
			t.Fatalf("transition to %s: %v", status, err)
		}
		if status == domain.InvestigationCompleted && current.CompletedAt == nil {
			t.Fatal("completed investigation has no completed_at")
		}
	}

	if _, err := repository.TransitionInvestigation(
		ctx,
		fixture.investigationID,
		6,
		domain.InvestigationFailed,
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal transition error = %v, want ErrInvalidTransition", err)
	}

	var status string
	var version int64
	if err := db.QueryRowContext(ctx, `
		SELECT status, version FROM investigations WHERE id = $1
	`, fixture.investigationID).Scan(&status, &version); err != nil {
		t.Fatalf("read investigation after rejected changes: %v", err)
	}
	if status != string(domain.InvestigationCompleted) || version != 6 {
		t.Fatalf("rejected changes modified investigation: status=%s version=%d", status, version)
	}
}

func TestReportReadsTraceableEvidenceAndDeployments(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "report")
	repository := NewPostgres(db)

	deployment, _, err := repository.CreateDeploymentEvent(ctx, fixture.deploymentInput("deploy-report-1"))
	if err != nil {
		t.Fatalf("create deployment event: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO deployment_candidates (
			project_id, incident_id, deployment_event_id, match_status, match_reason
		) VALUES ($1, $2, $3, 'MATCHED', 'same environment and service')
	`, fixture.projectID, fixture.incidentID, deployment.ID); err != nil {
		t.Fatalf("link deployment candidate: %v", err)
	}

	var toolCallID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO tool_calls (
			investigation_id, tool_name, status, completed_at, result_summary
		) VALUES (
			$1, 'query_metric_template', 'SUCCEEDED', now(), '{"series":3}'::jsonb
		)
		RETURNING id::text
	`, fixture.investigationID).Scan(&toolCallID); err != nil {
		t.Fatalf("insert tool call: %v", err)
	}
	var evidenceID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO evidence (
			investigation_id, tool_call_id, source_type, entity_type, entity_id,
			observed_start, observed_end, query_text, value_summary, completeness,
			independence_group, content_hash
		) VALUES (
			$1, $2, 'PROMETHEUS', 'service', $3, $4::timestamptz,
			$4::timestamptz + interval '5 minutes', 'latency_p95',
			'{"p95_ms":420}'::jsonb, 'COMPLETE', 'metrics', $5
		)
		RETURNING id::text
	`, fixture.investigationID, toolCallID, fixture.serviceID, fixture.startedAt,
		strings.Repeat("c", 64)).Scan(&evidenceID); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}
	var reportID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO reports (
			investigation_id, result_status, confidence, summary, recommendations,
			data_gaps, timeline
		) VALUES (
			$1, 'COMPLETED', 'HIGH', 'Deployment introduced a slow query',
			'["inspect query plan"]'::jsonb, '[]'::jsonb,
			'[{"at":"2026-11-04T05:00:00Z","kind":"deployment"}]'::jsonb
		)
		RETURNING id::text
	`, fixture.investigationID).Scan(&reportID); err != nil {
		t.Fatalf("insert report: %v", err)
	}

	report, err := repository.GetReport(ctx, reportID)
	if err != nil {
		t.Fatalf("get report: %v", err)
	}
	if len(report.Evidence) != 1 || report.Evidence[0].ID != evidenceID {
		t.Fatalf("report evidence = %#v, want evidence %s", report.Evidence, evidenceID)
	}
	if len(report.DeploymentEvents) != 1 || report.DeploymentEvents[0].ID != deployment.ID {
		t.Fatalf("report deployments = %#v, want deployment %s", report.DeploymentEvents, deployment.ID)
	}

	evidence, err := repository.GetEvidence(ctx, evidenceID)
	if err != nil {
		t.Fatalf("get evidence: %v", err)
	}
	if evidence.QueryText != "latency_p95" {
		t.Fatalf("evidence query = %q, want latency_p95", evidence.QueryText)
	}
	deploymentAgain, err := repository.GetDeploymentEvent(ctx, deployment.ID)
	if err != nil {
		t.Fatalf("get deployment event: %v", err)
	}
	if deploymentAgain.CommitSHA != fixture.commitSHA {
		t.Fatalf("deployment commit = %s, want %s", deploymentAgain.CommitSHA, fixture.commitSHA)
	}

	for name, read := range map[string]func() error{
		"report": func() error {
			_, err := repository.GetReport(ctx, "00000000-0000-4000-8000-000000000001")
			return err
		},
		"evidence": func() error {
			_, err := repository.GetEvidence(ctx, "00000000-0000-4000-8000-000000000002")
			return err
		},
		"deployment": func() error {
			_, err := repository.GetDeploymentEvent(ctx, "00000000-0000-4000-8000-000000000003")
			return err
		},
	} {
		if err := read(); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing %s error = %v, want ErrNotFound", name, err)
		}
	}
}

func TestGetInvestigationTimelineFiltersAndPaginatesDeterministically(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "investigation-timeline")
	base := fixture.startedAt.UTC().Truncate(time.Second)
	for _, item := range []struct {
		source       string
		entityType   string
		entityID     string
		observedAt   time.Time
		completeness string
		hash         string
	}{
		{"LOKI", "service", fixture.serviceID, base.Add(time.Minute), "PARTIAL", strings.Repeat("a", 64)},
		{"PROMETHEUS", "service", fixture.serviceID, base.Add(time.Minute), "COMPLETE", strings.Repeat("b", 64)},
		{"GITHUB", "release", fixture.releaseID, base.Add(2 * time.Minute), "COMPLETE", strings.Repeat("c", 64)},
	} {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO evidence (
				investigation_id, source_type, entity_type, entity_id,
				observed_start, observed_end, value_summary, completeness,
				independence_group, content_hash
			) VALUES ($1, $2, $3, $4, $5::timestamptz, $5::timestamptz + interval '30 seconds',
				'{}'::jsonb, $6, 'shared-source', $7)
		`, fixture.investigationID, item.source, item.entityType, item.entityID,
			item.observedAt, item.completeness, item.hash); err != nil {
			t.Fatalf("insert %s timeline evidence: %v", item.source, err)
		}
	}

	repository := NewPostgres(db)
	first, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{}, 2, 0)
	if err != nil {
		t.Fatalf("get first timeline page: %v", err)
	}
	if first.Total != 3 || len(first.Items) != 2 || !first.HasMore ||
		first.Items[0].SourceType != "LOKI" || first.Items[1].SourceType != "PROMETHEUS" {
		t.Fatalf("first page = %#v", first)
	}
	second, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{}, 2, 2)
	if err != nil {
		t.Fatalf("get second timeline page: %v", err)
	}
	if second.Total != 3 || len(second.Items) != 1 || second.HasMore || second.Items[0].SourceType != "GITHUB" {
		t.Fatalf("second page = %#v", second)
	}

	filtered, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{
		SourceType: "LOKI", EntityID: fixture.serviceID, Completeness: "PARTIAL",
	}, 20, 0)
	if err != nil {
		t.Fatalf("get filtered timeline: %v", err)
	}
	if filtered.Total != 1 || len(filtered.Items) != 1 || filtered.Items[0].SourceType != "LOKI" {
		t.Fatalf("filtered timeline = %#v", filtered)
	}

	empty, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{
		SourceType: "RUNTIME",
	}, 20, 0)
	if err != nil || empty.Total != 0 || empty.Items == nil || empty.HasMore {
		t.Fatalf("empty timeline = %#v, err=%v", empty, err)
	}
	if _, err := repository.GetInvestigationTimeline(ctx,
		"ffffffff-ffff-4fff-8fff-ffffffffffff", InvestigationTimelineFilter{}, 20, 0,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing investigation error = %v, want ErrNotFound", err)
	}
}

func TestGetInvestigationTimelineRejectsInvalidInputsBeforeDatabaseAccess(t *testing.T) {
	repository := NewPostgres(nil)
	validID := "44444444-4444-4444-8444-444444444444"
	for _, testCase := range []struct {
		name   string
		id     string
		filter InvestigationTimelineFilter
		limit  int
		offset int
	}{
		{name: "bad ID", id: "bad", limit: 1},
		{name: "bad source", id: validID, filter: InvestigationTimelineFilter{SourceType: "UNKNOWN"}, limit: 1},
		{name: "bad completeness", id: validID, filter: InvestigationTimelineFilter{Completeness: "INVALID"}, limit: 1},
		{name: "bad stance", id: validID, filter: InvestigationTimelineFilter{Stance: "INVALID"}, limit: 1},
		{name: "oversized page", id: validID, limit: 101},
		{name: "negative offset", id: validID, limit: 1, offset: -1},
		{name: "oversized offset", id: validID, limit: 1, offset: 10001},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := repository.GetInvestigationTimeline(
				context.Background(), testCase.id, testCase.filter, testCase.limit, testCase.offset,
			)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestTimelineStanceFiltersRelationsWithoutDuplicates(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "timeline-stance")
	other := insertStoreFixture(t, ctx, db, "timeline-stance-other")
	insertEvidence := func(owner storeFixture, source, hash string) string {
		var id string
		err := db.QueryRowContext(ctx, `INSERT INTO evidence
			(investigation_id, source_type, entity_type, entity_id, observed_start, observed_end,
			 value_summary, completeness, independence_group, content_hash)
			VALUES ($1, $2, 'service', $3, $4, $4, '{}', 'COMPLETE', 'test', $5) RETURNING id::text`,
			owner.investigationID, source, owner.serviceID, owner.startedAt, strings.Repeat(hash, 64)).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	insertHypothesis := func(owner storeFixture, rank int) string {
		var id string
		err := db.QueryRowContext(ctx, `INSERT INTO hypotheses
			(investigation_id, rank, entity, fault_type, mechanism, affected_scope, confidence, summary)
			VALUES ($1, $2, 'service', 'fault', 'mechanism', 'scope', 'LOW', 'summary') RETURNING id::text`,
			owner.investigationID, rank).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	link := func(owner storeFixture, hypothesis, item, stance string) {
		_, err := db.ExecContext(ctx, `INSERT INTO hypothesis_evidence
			(investigation_id, hypothesis_id, evidence_id, stance) VALUES ($1, $2, $3, $4)`,
			owner.investigationID, hypothesis, item, stance)
		if err != nil {
			t.Fatal(err)
		}
	}
	first := insertEvidence(fixture, "LOKI", "a")
	second := insertEvidence(fixture, "PROMETHEUS", "b")
	third := insertEvidence(fixture, "SYSTEM", "d")
	unlinked := insertEvidence(fixture, "RUNTIME", "e")
	foreign := insertEvidence(other, "LOKI", "c")
	h1, h2 := insertHypothesis(fixture, 1), insertHypothesis(fixture, 2)
	link(fixture, h1, first, "SUPPORTS")
	link(fixture, h2, first, "CONTRADICTS")
	link(fixture, h1, second, "CONTRADICTS")
	link(fixture, h2, third, "SUPPORTS")
	link(other, insertHypothesis(other, 1), foreign, "SUPPORTS")
	repository := NewPostgres(db)
	for _, tc := range []struct{ stance, source, want string }{
		{"CONTRADICTS", "PROMETHEUS", second}, {"CONTRADICTS", "LOKI", first}, {"SUPPORTS", "LOKI", first},
	} {
		got, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID,
			InvestigationTimelineFilter{Stance: tc.stance, SourceType: tc.source}, 1, 0)
		if err != nil || got.Total != 1 || len(got.Items) != 1 || got.Items[0].ID != tc.want || got.HasMore {
			t.Fatalf("stance %s source %s: got %+v, err %v", tc.stance, tc.source, got, err)
		}
		if got.Items[0].ID == first {
			relations := make(map[string]string, len(got.Items[0].Relations))
			for _, relation := range got.Items[0].Relations {
				relations[relation.HypothesisID] = relation.Stance
			}
			if len(relations) != 2 || relations[h1] != "SUPPORTS" || relations[h2] != "CONTRADICTS" {
				t.Fatalf("relations for %s = %#v", tc.stance, got.Items[0].Relations)
			}
		}
	}
	page, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID,
		InvestigationTimelineFilter{Stance: "SUPPORTS"}, 1, 0)
	if err != nil || page.Total != 2 || len(page.Items) != 1 || page.Items[0].ID != first || !page.HasMore {
		t.Fatalf("first page: got %+v, err %v", page, err)
	}
	page, err = repository.GetInvestigationTimeline(ctx, fixture.investigationID,
		InvestigationTimelineFilter{Stance: "SUPPORTS"}, 1, 1)
	if err != nil || page.Total != 2 || len(page.Items) != 1 || page.Items[0].ID != third || page.HasMore {
		t.Fatalf("second page: got %+v, err %v", page, err)
	}
	page, err = repository.GetInvestigationTimeline(ctx, fixture.investigationID,
		InvestigationTimelineFilter{}, 10, 0)
	if err != nil || page.Total != 4 {
		t.Fatalf("unfiltered page: got %+v, err %v", page, err)
	}
	for _, item := range page.Items {
		if item.ID == unlinked && (item.Relations == nil || len(item.Relations) != 0) {
			t.Fatalf("unlinked evidence relations = %#v, want empty array", item.Relations)
		}
	}
}

type storeFixture struct {
	projectID       string
	serviceID       string
	releaseID       string
	incidentID      string
	investigationID string
	startedAt       time.Time
	commitSHA       string
	imageDigest     string
}

func (fixture storeFixture) deploymentInput(idempotencyKey string) CreateDeploymentEventInput {
	return CreateDeploymentEventInput{
		ProjectID:      fixture.projectID,
		ServiceID:      fixture.serviceID,
		ReleaseID:      fixture.releaseID,
		Environment:    "prod",
		SourceSystem:   "ci",
		IdempotencyKey: idempotencyKey,
		Status:         "SUCCEEDED",
		StartedAt:      fixture.startedAt,
		FinishedAt:     pointerTo(fixture.startedAt.Add(2 * time.Minute)),
		Version:        "v1.2.3",
		CommitSHA:      fixture.commitSHA,
		ImageDigest:    fixture.imageDigest,
		InstanceCount:  2,
		SourceTimezone: "Asia/Shanghai",
		SourceTimeText: "2026-11-04T13:00:00+08:00",
		Metadata:       json.RawMessage(`{"pipeline":"checkout-main"}`),
	}
}

func (fixture storeFixture) alertInput(idempotencyKey string) CreateAlertInput {
	return CreateAlertInput{
		ProjectID:      fixture.projectID,
		ServiceID:      fixture.serviceID,
		Environment:    "prod",
		Fingerprint:    "checkout-latency",
		IdempotencyKey: idempotencyKey,
		Status:         "FIRING",
		Severity:       "ERROR",
		Summary:        "Checkout latency is elevated",
		StartsAt:       fixture.startedAt,
		Labels:         json.RawMessage(`{"service":"checkout-api"}`),
		Annotations:    json.RawMessage(`{"dashboard":"checkout"}`),
		RedactedPayload: json.RawMessage(
			`{"receiver":"relythra","status":"firing"}`,
		),
		SourceTimezone: "Asia/Shanghai",
		SourceTimeText: "2026-11-04T13:00:00+08:00",
	}
}

func openStoreTestDB(t *testing.T) *sql.DB {
	t.Helper()
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
	schema := fmt.Sprintf("relythra_store_test_%d", time.Now().UnixNano())
	if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create isolated schema: %v", err)
	}

	testURL, err := url.Parse(databaseURL)
	if err != nil {
		_ = adminDB.Close()
		t.Fatalf("parse test database URL: %v", err)
	}
	query := testURL.Query()
	query.Set("search_path", schema)
	testURL.RawQuery = query.Encode()
	db, err := sql.Open("pgx", testURL.String())
	if err != nil {
		_ = adminDB.Close()
		t.Fatalf("open isolated database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = adminDB.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = adminDB.Close()
	})

	goose.SetBaseFS(migrations.Files)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set goose dialect: %v", err)
	}
	if err := goose.UpContext(ctx, db, "."); err != nil {
		t.Fatalf("migrate isolated database: %v", err)
	}
	return db
}

func insertStoreFixture(t *testing.T, ctx context.Context, db *sql.DB, slug string) storeFixture {
	t.Helper()
	fixture := storeFixture{
		startedAt:   time.Date(2026, 11, 4, 5, 0, 0, 0, time.UTC),
		commitSHA:   strings.Repeat("a", 40),
		imageDigest: "sha256:" + strings.Repeat("b", 64),
	}
	if err := db.QueryRowContext(ctx, `
		INSERT INTO projects (slug, name) VALUES ($1, $1) RETURNING id::text
	`, slug).Scan(&fixture.projectID); err != nil {
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
			project_id, service_id, version, commit_sha, image_digest
		) VALUES ($1, $2, 'v1.2.3', $3, $4)
		RETURNING id::text
	`, fixture.projectID, fixture.serviceID, fixture.commitSHA, fixture.imageDigest).Scan(&fixture.releaseID); err != nil {
		t.Fatalf("insert release: %v", err)
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

func pointerTo[T any](value T) *T {
	return &value
}
