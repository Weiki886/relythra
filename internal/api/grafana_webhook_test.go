package api

import (
	"encoding/json"
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

func TestParseGrafanaWebhookNormalizesAlertAndDerivesVersionedFingerprint(t *testing.T) {
	t.Parallel()

	payload := `{"receiver":"relythra","status":"firing","alerts":[{"status":"firing","labels":{"project":"store","service":"checkout-api","env":"prod","alertname":"HighLatency"},"annotations":{"summary":"P95 latency is high"},"startsAt":"2026-11-05T12:00:00Z","endsAt":"0001-01-01T00:00:00Z","generatorURL":"https://grafana.example.test/alerting/grafana/abc"}]}`
	parsed, err := ParseGrafanaWebhook([]byte(payload))
	if err != nil {
		t.Fatalf("ParseGrafanaWebhook: %v", err)
	}
	if len(parsed.Alerts) != 1 {
		t.Fatalf("alert count = %d, want 1", len(parsed.Alerts))
	}
	alert := parsed.Alerts[0]
	if alert.ProjectSlug != "store" || alert.ServiceSlug != "checkout-api" || alert.Environment != "prod" ||
		alert.Status != "FIRING" || alert.Summary != "P95 latency is high" || alert.Fingerprint == "" ||
		alert.FingerprintVersion != "sha256-v1" || alert.EndsAt != nil {
		t.Fatalf("normalized alert = %+v", alert)
	}
	if _, err := time.Parse(time.RFC3339Nano, alert.StartsAt.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("normalized start time is invalid: %v", err)
	}
}

func TestParseGrafanaWebhookPreservesGrafanaValuesAndOriginalTimestamp(t *testing.T) {
	t.Parallel()

	payload := `{"receiver":"relythra","status":"firing","alerts":[{"status":"firing","labels":{"project":"store","service":"checkout-api","env":"prod","alertname":"HighLatency"},"annotations":{"summary":"high"},"startsAt":"2026-11-05T20:00:00.123+08:00","values":{"A":123.5,"B":0},"valueString":"[ var='A' value=123.5 ]"}]}`
	parsed, err := ParseGrafanaWebhook([]byte(payload))
	if err != nil {
		t.Fatalf("ParseGrafanaWebhook with standard values: %v", err)
	}
	alert := parsed.Alerts[0]
	if alert.Values["A"] != 123.5 || alert.Values["B"] != 0 {
		t.Fatalf("Grafana values = %#v", alert.Values)
	}
	if alert.SourceTimeText != "2026-11-05T20:00:00.123+08:00" || alert.SourceTimezone != "+08:00" {
		t.Fatalf("source timestamp = %q timezone %q", alert.SourceTimeText, alert.SourceTimezone)
	}
	if alert.StartsAt.Format(time.RFC3339Nano) != "2026-11-05T12:00:00.123Z" {
		t.Fatalf("normalized timestamp = %s", alert.StartsAt.Format(time.RFC3339Nano))
	}
}

func TestParseGrafanaWebhookAllowsMissingAnnotationsAndUsesAlertName(t *testing.T) {
	t.Parallel()

	payload := `{"alerts":[{"status":"firing","labels":{"project":"store","service":"checkout-api","env":"prod","alertname":"HighLatency"},"startsAt":"2026-11-05T12:00:00Z"}]}`
	parsed, err := ParseGrafanaWebhook([]byte(payload))
	if err != nil {
		t.Fatalf("ParseGrafanaWebhook without annotations: %v", err)
	}
	if got := parsed.Alerts[0].Summary; got != "HighLatency" {
		t.Fatalf("summary = %q, want alertname fallback", got)
	}
}

func TestGrafanaWebhookRequiresValidSignatureAndRejectsReplay(t *testing.T) {
	repository := &fakeDeploymentRepository{grafanaResults: []store.GrafanaAlertResult{{
		Alert: store.Alert{ID: deploymentID}, IncidentID: "incident-id", MatchState: "MATCHED", Created: true,
	}}}
	recorder := &capturingAuditRecorder{}
	secret, err := secrets.New("grafana-secret")
	if err != nil {
		t.Fatal(err)
	}
	filter, err := redact.NewFilter("configured-ingestion-canary")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandlerWithDependencies(Dependencies{
		GrafanaWebhookSecret: secret, GrafanaAlerts: repository, AuditRecorder: recorder,
	}, discardLogger(), filter)
	body := `{"receiver":"relythra","status":"firing","alerts":[{"status":"firing","labels":{"project":"store","service":"checkout-api","env":"prod","alertname":"HighLatency"},"annotations":{"summary":"high"},"startsAt":"2026-11-05T20:00:00.123+08:00"}]}`
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := SignDeploymentRequest([]byte("grafana-secret"), timestamp, []byte(body))
	request := func(sig string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/grafana", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Relythra-Timestamp", timestamp)
		req.Header.Set("X-Relythra-Signature", sig)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	bad := request("sha256=" + strings.Repeat("0", 64))
	assertErrorResponse(t, bad, http.StatusUnauthorized, "invalid_signature")
	if repository.claimCalls != 0 || len(repository.grafanaInputs) != 0 {
		t.Fatalf("invalid signature produced claim=%d ingestion=%d", repository.claimCalls, len(repository.grafanaInputs))
	}
	first := request(signature)
	if first.Code != http.StatusCreated {
		t.Fatalf("first request status = %d: %s", first.Code, first.Body.String())
	}
	if len(repository.grafanaInputs) != 1 || repository.grafanaRequestID == "" {
		t.Fatalf("Grafana ingestion input = %+v, request=%q", repository.grafanaInputs, repository.grafanaRequestID)
	}
	if repository.grafanaInputs[0].SourceTimeText != "2026-11-05T20:00:00.123+08:00" || repository.grafanaInputs[0].SourceTimezone != "+08:00" ||
		repository.grafanaInputs[0].StartsAt.Format(time.RFC3339Nano) != "2026-11-05T12:00:00.123Z" {
		t.Fatalf("Grafana source/normalized times = %q / %q / %s", repository.grafanaInputs[0].SourceTimeText,
			repository.grafanaInputs[0].SourceTimezone, repository.grafanaInputs[0].StartsAt.Format(time.RFC3339Nano))
	}
	if repository.grafanaFilter != filter {
		t.Fatal("configured filter did not reach ingestion")
	}
	second := request(signature)
	assertErrorResponse(t, second, http.StatusConflict, "replayed_signature")
	if repository.claimCalls != 2 || len(repository.grafanaInputs) != 1 {
		t.Fatalf("replay claim=%d ingestion count=%d", repository.claimCalls, len(repository.grafanaInputs))
	}
	var envelope struct {
		Data struct {
			Items []store.GrafanaAlertResult `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &envelope); err != nil || len(envelope.Data.Items) != 1 {
		t.Fatalf("decode successful response: items=%d err=%v", len(envelope.Data.Items), err)
	}
}

func TestGrafanaWebhookBatchReturnsAcceptedWhenAnyAlertNeedsMapping(t *testing.T) {
	results := []store.GrafanaAlertResult{
		{Alert: store.Alert{ID: "first"}, MatchState: "NEEDS_MAPPING", Created: true},
		{Alert: store.Alert{ID: "second"}, MatchState: "MATCHED", Created: true},
	}
	repository := &fakeDeploymentRepository{grafanaResults: results}
	recorder := &capturingAuditRecorder{}
	secret, err := secrets.New("grafana-secret")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandlerWithDependencies(Dependencies{
		GrafanaWebhookSecret: secret, GrafanaAlerts: repository, AuditRecorder: recorder,
	}, discardLogger())
	body := `{"receiver":"relythra","status":"firing","alerts":[{"status":"firing","labels":{"project":"store","service":"unknown","env":"prod","alertname":"A"},"annotations":{"summary":"A"},"startsAt":"2026-11-05T12:00:00Z"},{"status":"firing","labels":{"project":"store","service":"checkout-api","env":"prod","alertname":"B"},"annotations":{"summary":"B"},"startsAt":"2026-11-05T12:01:00Z"}]}`
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/grafana", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Relythra-Timestamp", timestamp)
	request.Header.Set("X-Relythra-Signature", SignDeploymentRequest([]byte("grafana-secret"), timestamp, []byte(body)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("mixed batch status = %d, want 202: %s", response.Code, response.Body.String())
	}
}

func TestGrafanaWebhookRejectsNonJSONMediaTypePrefix(t *testing.T) {
	recorder := &capturingAuditRecorder{}
	secret, err := secrets.New("grafana-secret")
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeDeploymentRepository{}
	handler := NewHandlerWithDependencies(Dependencies{
		GrafanaWebhookSecret: secret, GrafanaAlerts: repository, AuditRecorder: recorder,
	}, discardLogger())
	request := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/grafana", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/jsonp")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertErrorResponse(t, response, http.StatusUnsupportedMediaType, "unsupported_media_type")
	if repository.claimCalls != 0 || len(repository.grafanaInputs) != 0 {
		t.Fatalf("unsupported media type produced claim=%d ingestion=%d", repository.claimCalls, len(repository.grafanaInputs))
	}
}

func TestGrafanaAlertManualRemappingRequiresManagementAuthAndExpectedVersion(t *testing.T) {
	repository := &fakeDeploymentRepository{}
	recorder := &capturingAuditRecorder{}
	filter, err := redact.NewFilter("configured-remapping-canary")
	if err != nil {
		t.Fatal(err)
	}
	handler := newDeploymentTestHandler(t, repository, "grafana-secret", recorder, filter)
	body := `{"expected_version":1,"service_id":"` + deploymentServiceID + `","environment":"prod"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/33333333-3333-4333-8333-333333333333/remap", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer management-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("remap status = %d: %s", response.Code, response.Body.String())
	}
	if repository.grafanaFilter != filter {
		t.Fatal("configured filter did not reach remapping")
	}
	if recorder.eventCount() != 1 || recorder.lastEvent(t).Action != audit.ActionAlertMappingChanged {
		t.Fatalf("remap audit = %+v", recorder.lastEvent(t))
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/alerts/33333333-3333-4333-8333-333333333333/remap", strings.NewReader(`{"service_id":"`+deploymentServiceID+`","environment":"prod"}`))
	request.Header.Set("Authorization", "Bearer management-token")
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertErrorResponse(t, response, http.StatusBadRequest, "invalid_request")
}

func TestParseGrafanaWebhookRejectsMalformedOrUnboundedInput(t *testing.T) {
	t.Parallel()

	valid := `{"status":"firing","alerts":[{"status":"firing","labels":{"project":"store","service":"checkout-api","env":"prod","alertname":"HighLatency"},"annotations":{"summary":"high"},"startsAt":"2026-11-05T12:00:00Z"}]}`
	tests := []struct {
		name string
		body string
	}{
		{name: "unknown field", body: strings.Replace(valid, `"status":"firing"`, `"unknown":true,"status":"firing"`, 1)},
		{name: "no alerts", body: `{"status":"firing","alerts":[]}`},
		{name: "missing start", body: strings.Replace(valid, `,"startsAt":"2026-11-05T12:00:00Z"`, "", 1)},
		{name: "oversized summary", body: strings.Replace(valid, `"high"`, `"`+strings.Repeat("x", maxGrafanaAnnotationLength+1)+`"`, 1)},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseGrafanaWebhook([]byte(testCase.body)); err == nil {
				t.Fatal("ParseGrafanaWebhook() error = nil, want validation error")
			}
		})
	}
}
