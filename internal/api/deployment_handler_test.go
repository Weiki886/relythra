package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/security/audit"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/security/secrets"
	"github.com/Weiki886/relythra/internal/store"
)

const (
	deploymentProjectID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	deploymentServiceID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	deploymentReleaseID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

type fakeDeploymentRepository struct {
	event            store.DeploymentEvent
	created          bool
	createInput      store.CreateDeploymentEventInput
	updateInput      store.UpdateDeploymentEventInput
	updateID         string
	query            store.DeploymentCandidateQuery
	candidates       []store.DeploymentEvent
	err              error
	createCalls      int
	updateCalls      int
	queryCalls       int
	claimed          map[string]bool
	claimCalls       int
	grafanaInputs    []store.GrafanaAlertInput
	grafanaFilter    *redact.Filter
	grafanaRequestID string
	grafanaResults   []store.GrafanaAlertResult
}

func (repository *fakeDeploymentRepository) IngestGrafanaAlerts(
	_ context.Context,
	inputs []store.GrafanaAlertInput,
	requestID string,
	filter *redact.Filter,
) ([]store.GrafanaAlertResult, error) {
	repository.grafanaFilter = filter
	repository.grafanaInputs = inputs
	repository.grafanaRequestID = requestID
	return repository.grafanaResults, repository.err
}

func (repository *fakeDeploymentRepository) RemapGrafanaAlert(
	_ context.Context,
	alertID string,
	expectedVersion int64,
	serviceID string,
	environment string,
	filter *redact.Filter,
) (store.GrafanaAlertResult, error) {
	repository.grafanaFilter = filter
	return store.GrafanaAlertResult{
		Alert:      store.Alert{ID: alertID, EventVersion: expectedVersion + 1},
		IncidentID: "incident-id", MatchState: "MATCHED",
	}, repository.err
}

func (repository *fakeDeploymentRepository) CreateDeploymentEvent(
	_ context.Context,
	input store.CreateDeploymentEventInput,
) (store.DeploymentEvent, bool, error) {
	repository.createCalls++
	repository.createInput = input
	if repository.event.ID == "" {
		repository.event = store.DeploymentEvent{ID: deploymentID, Status: input.Status, EventVersion: 1}
	}
	return repository.event, repository.created || repository.createCalls == 1, repository.err
}

func (repository *fakeDeploymentRepository) UpdateDeploymentEvent(
	_ context.Context,
	id string,
	input store.UpdateDeploymentEventInput,
) (store.DeploymentEvent, error) {
	repository.updateCalls++
	repository.updateID = id
	repository.updateInput = input
	repository.event.Status = input.Status
	repository.event.EventVersion = input.ExpectedVersion + 1
	return repository.event, repository.err
}

func (repository *fakeDeploymentRepository) FindDeploymentCandidates(
	_ context.Context,
	query store.DeploymentCandidateQuery,
) ([]store.DeploymentEvent, error) {
	repository.queryCalls++
	repository.query = query
	return repository.candidates, repository.err
}

func (repository *fakeDeploymentRepository) ClaimDeploymentWebhookSignature(
	_ context.Context,
	digest []byte,
	_ time.Time,
) (bool, error) {
	repository.claimCalls++
	if repository.claimed == nil {
		repository.claimed = make(map[string]bool)
	}
	key := string(digest)
	if repository.claimed[key] {
		return false, nil
	}
	repository.claimed[key] = true
	return true, nil
}

func TestDeploymentWebhookRejectsMissingAndInvalidSignatureBeforeWrite(t *testing.T) {
	repository := &fakeDeploymentRepository{}
	recorder := &capturingAuditRecorder{}
	handler := newDeploymentTestHandler(t, repository, "deployment-secret", recorder)
	body := validDeploymentRequestBody()

	for _, testCase := range []struct {
		name      string
		timestamp string
		signature string
	}{
		{name: "missing signature"},
		{name: "invalid signature", timestamp: strconv.FormatInt(time.Now().Unix(), 10), signature: "sha256=" + strings.Repeat("0", 64)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/deployment-events/webhook", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Relythra-Timestamp", testCase.timestamp)
			request.Header.Set("X-Relythra-Signature", testCase.signature)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertErrorResponse(t, response, http.StatusUnauthorized, "invalid_signature")
		})
	}
	if repository.createCalls != 0 {
		t.Fatalf("repository create calls = %d, want 0", repository.createCalls)
	}
}

func TestDeploymentWebhookCreatesSignedEventWithConfiguredSource(t *testing.T) {
	repository := &fakeDeploymentRepository{}
	recorder := &capturingAuditRecorder{}
	handler := newDeploymentTestHandler(t, repository, "deployment-secret", recorder)
	body := validDeploymentRequestBody()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/deployment-events/webhook", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Relythra-Timestamp", timestamp)
	request.Header.Set("X-Relythra-Signature", SignDeploymentRequest([]byte("deployment-secret"), timestamp, []byte(body)))
	request.Header.Set("X-Request-ID", "deployment-request-42")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", response.Code, response.Body.String())
	}
	if repository.createCalls != 1 || repository.createInput.SourceSystem != "github-actions" ||
		repository.createInput.IdempotencyKey != "github-actions:external-42" ||
		repository.createInput.RequestID != "deployment-request-42" {
		t.Fatalf("deployment input = %+v; calls=%d", repository.createInput, repository.createCalls)
	}
	if !strings.Contains(string(repository.createInput.Metadata), "external-42") {
		t.Fatal("redacted source payload was not retained in deployment metadata")
	}
	if recorder.eventCount() != 1 || recorder.lastEvent(t).Action != audit.ActionWebhookReceived {
		t.Fatalf("webhook audit events = %d, last=%+v", recorder.eventCount(), recorder.lastEvent(t))
	}
}

func TestDeploymentWebhookRejectsReplayedSignatureBeforeWrite(t *testing.T) {
	repository := &fakeDeploymentRepository{}
	recorder := &capturingAuditRecorder{}
	handler := newDeploymentTestHandler(t, repository, "deployment-secret", recorder)
	body := validDeploymentRequestBody()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := SignDeploymentRequest([]byte("deployment-secret"), timestamp, []byte(body))
	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/deployment-events/webhook", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Relythra-Timestamp", timestamp)
		req.Header.Set("X-Relythra-Signature", signature)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}

	if response := request(); response.Code != http.StatusCreated {
		t.Fatalf("first request status = %d, want 201: %s", response.Code, response.Body.String())
	}
	response := request()
	assertErrorResponse(t, response, http.StatusConflict, "replayed_signature")
	if repository.claimCalls != 2 || repository.createCalls != 1 {
		t.Fatalf("claim calls = %d, create calls = %d; want 2 claims and 1 create", repository.claimCalls, repository.createCalls)
	}
}

func TestDeploymentWebhookBodyLimitAndStrictSchema(t *testing.T) {
	for _, testCase := range []struct {
		name string
		body string
	}{
		{name: "unknown field", body: strings.TrimSuffix(validDeploymentRequestBody(), "}") + `,"unexpected":true}`},
		{name: "body too large", body: strings.Repeat(" ", maxDeploymentWebhookBodyBytes+1)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			repository := &fakeDeploymentRepository{}
			recorder := &capturingAuditRecorder{}
			handler := newDeploymentTestHandler(t, repository, "deployment-secret", recorder)
			timestamp := strconv.FormatInt(time.Now().Unix(), 10)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/deployment-events/webhook", strings.NewReader(testCase.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Relythra-Timestamp", timestamp)
			request.Header.Set("X-Relythra-Signature", SignDeploymentRequest([]byte("deployment-secret"), timestamp, []byte(testCase.body)))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code < 400 || repository.createCalls != 0 {
				t.Fatalf("response=%d calls=%d body=%s", response.Code, repository.createCalls, response.Body.String())
			}
		})
	}
}

func TestManualDeploymentCreateRequiresAdminAndRecordsManagementActor(t *testing.T) {
	repository := &fakeDeploymentRepository{}
	recorder := &capturingAuditRecorder{}
	handler := newDeploymentTestHandler(t, repository, "", recorder)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/deployment-events", strings.NewReader(validDeploymentRequestBody()))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer management-token")
	request.Header.Set("X-Request-ID", "manual-deployment-42")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", response.Code, response.Body.String())
	}
	if repository.createInput.SourceSystem != "manual" || repository.createInput.IdempotencyKey != "manual:external-42" {
		t.Fatalf("manual deployment input = %+v", repository.createInput)
	}
	if recorder.eventCount() != 1 || recorder.lastEvent(t).ObjectType != "deployment_event" {
		t.Fatalf("management audit event = %+v", recorder.lastEvent(t))
	}
}

func TestManualDeploymentCorrectionRequiresExpectedVersionAndReason(t *testing.T) {
	repository := &fakeDeploymentRepository{event: store.DeploymentEvent{ID: deploymentID, EventVersion: 4, Status: "IN_PROGRESS"}}
	recorder := &capturingAuditRecorder{}
	handler := newDeploymentTestHandler(t, repository, "", recorder)
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/deployment-events/"+deploymentID, strings.NewReader(`{"expected_version":4,"reason":"correct CI facts","commit_sha":"`+strings.Repeat("d", 40)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer management-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || repository.updateCalls != 1 {
		t.Fatalf("status=%d updateCalls=%d response=%s", response.Code, repository.updateCalls, response.Body.String())
	}
	if repository.updateInput.ExpectedVersion != 4 || repository.updateInput.Actor != "local-operator" || repository.updateInput.Reason != "correct CI facts" {
		t.Fatalf("correction input = %+v", repository.updateInput)
	}
}

func TestDeploymentCandidateQueryReturnsAmbiguousStateForMultipleDeployments(t *testing.T) {
	repository := &fakeDeploymentRepository{candidates: []store.DeploymentEvent{{ID: deploymentID}, {ID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd"}}}
	recorder := &capturingAuditRecorder{}
	handler := newDeploymentTestHandler(t, repository, "", recorder)
	start := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	request := httptest.NewRequest(http.MethodGet, fmt.Sprintf(
		"/api/v1/deployment-events/candidates?project_id=%s&service_id=%s&environment=prod&start=%s&end=%s",
		deploymentProjectID, deploymentServiceID, start.Format(time.RFC3339), end.Format(time.RFC3339)), nil)
	request.Header.Set("Authorization", "Bearer management-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || repository.queryCalls != 1 || repository.query.Limit != 20 {
		t.Fatalf("status=%d query=%+v body=%s", response.Code, repository.query, response.Body.String())
	}
	var envelope struct {
		Data deploymentCandidateResponse `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode candidates: %v", err)
	}
	if envelope.Data.MatchState != "AMBIGUOUS" || len(envelope.Data.Items) != 2 {
		t.Fatalf("candidate response = %+v", envelope.Data)
	}
}

func newDeploymentTestHandler(
	t *testing.T,
	repository *fakeDeploymentRepository,
	webhookSecret string,
	recorder *capturingAuditRecorder,
	filters ...*redact.Filter,
) http.Handler {
	t.Helper()
	var secret secrets.Secret
	if webhookSecret != "" {
		var err error
		secret, err = secrets.New(webhookSecret)
		if err != nil {
			t.Fatal(err)
		}
	}
	return NewHandlerWithDependencies(Dependencies{
		Deployments:             repository,
		GrafanaAlerts:           repository,
		AdminAuthenticator:      mustAuthenticator(t, "management-token"),
		AuditRecorder:           recorder,
		DeploymentWebhookSecret: secret,
		DeploymentWebhookSource: "github-actions",
		GrafanaWebhookSecret:    secret,
		ManagementActor:         "local-operator",
	}, discardLogger(), filters...)
}

func validDeploymentRequestBody() string {
	return fmt.Sprintf(`{
		"external_deployment_id":"external-42",
		"project_id":%q,
		"service_id":%q,
		"release_id":%q,
		"environment":"prod",
		"status":"SUCCEEDED",
		"started_at":"2026-11-05T09:00:00Z",
		"finished_at":"2026-11-05T09:05:00Z",
		"version":"v1.2.3",
		"commit_sha":"%s",
		"image_digest":"sha256:%s",
		"instance_count":2,
		"source_reference":"https://ci.example.test/runs/42",
		"source_timezone":"UTC",
		"source_time_text":"2026-11-05T09:05:00Z",
		"metadata":{"pipeline":"checkout"}
	}`, deploymentProjectID, deploymentServiceID, deploymentReleaseID, strings.Repeat("a", 40), strings.Repeat("b", 64))
}
