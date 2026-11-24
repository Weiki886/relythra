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

	"github.com/Weiki886/relythra/internal/security/secrets"
	"github.com/Weiki886/relythra/internal/store"
)

// Project, service and release are configuration fixtures. Deployment and alert
// facts are created only through their public HTTP entry points.
func TestDeploymentAlertInvestigationTimelineIntegration(t *testing.T) {
	db := openDiagnosisTestDB(t)
	ctx := context.Background()
	var projectID, serviceID, releaseID string
	if err := db.QueryRowContext(ctx, `INSERT INTO projects (slug, name) VALUES ('demo', 'Demo') RETURNING id::text`).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO services (project_id, slug, name) VALUES ($1, 'inventory', 'Inventory') RETURNING id::text`, projectID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("a", 40)
	if err := db.QueryRowContext(ctx, `INSERT INTO releases (project_id, service_id, version, commit_sha) VALUES ($1, $2, 'v1', $3) RETURNING id::text`, projectID, serviceID, commit).Scan(&releaseID); err != nil {
		t.Fatal(err)
	}
	repository := store.NewPostgres(db)
	deploymentSecret, err := secrets.New("test-deployment-signing-key")
	if err != nil {
		t.Fatal(err)
	}
	alertSecret, err := secrets.New("test-alert-signing-key")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandlerWithDependencies(Dependencies{
		Reader: repository, Deployments: repository, GrafanaAlerts: repository,
		DeploymentWebhookSecret: deploymentSecret, DeploymentWebhookSource: "ci",
		GrafanaWebhookSecret: alertSecret, AuditRecorder: &capturingAuditRecorder{},
	}, discardLogger())
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	post := func(path, body, key string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Relythra-Timestamp", timestamp)
		request.Header.Set("X-Relythra-Signature", SignDeploymentRequest([]byte(key), timestamp, []byte(body)))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	deploymentBody := fmt.Sprintf(`{"external_deployment_id":"demo-release-1","project_id":%q,"service_id":%q,"release_id":%q,"environment":"demo","status":"SUCCEEDED","started_at":"2025-01-01T00:00:00Z","finished_at":"2025-01-01T00:01:00Z","version":"v1","commit_sha":%q,"instance_count":1,"source_reference":"https://ci.example.test/run/1","source_timezone":"UTC","source_time_text":"2025-01-01T00:00:00Z","metadata":{}}`, projectID, serviceID, releaseID, commit)
	deployment := post("/api/v1/deployment-events/webhook", deploymentBody, "test-deployment-signing-key")
	if deployment.Code != http.StatusCreated {
		t.Fatalf("deployment status=%d body=%s", deployment.Code, deployment.Body.String())
	}
	var deploymentResult struct {
		Data store.DeploymentEvent `json:"data"`
	}
	if err := json.Unmarshal(deployment.Body.Bytes(), &deploymentResult); err != nil {
		t.Fatal(err)
	}
	if deploymentResult.Data.ID == "" {
		t.Fatal("deployment event ID missing")
	}
	alertBody := `{"receiver":"relythra","status":"firing","alerts":[{"status":"firing","fingerprint":"integration-alert-1","labels":{"project":"demo","service":"inventory","env":"demo","alertname":"Latency"},"annotations":{"summary":"Inventory latency"},"startsAt":"2025-01-01T00:02:00Z","generatorURL":"https://grafana.example.test/alert/1"}]}`
	alert := post("/api/v1/alerts/grafana", alertBody, "test-alert-signing-key")
	if alert.Code != http.StatusCreated {
		t.Fatalf("alert status=%d body=%s", alert.Code, alert.Body.String())
	}
	replay := post("/api/v1/alerts/grafana", alertBody, "test-alert-signing-key")
	if replay.Code != http.StatusConflict || !strings.Contains(replay.Body.String(), "replayed_signature") {
		t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	var alertResult struct {
		Data struct {
			Items []store.GrafanaAlertResult `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(alert.Body.Bytes(), &alertResult); err != nil {
		t.Fatal(err)
	}
	if len(alertResult.Data.Items) != 1 {
		t.Fatalf("alert items = %+v", alertResult.Data.Items)
	}
	item := alertResult.Data.Items[0]
	if item.InvestigationID == "" || item.MatchState != "MATCHED" || item.DeploymentCount != 1 {
		t.Fatalf("alert result = %+v", item)
	}
	readTimeline := func() store.InvestigationTimeline {
		t.Helper()
		response := serve(handler, http.MethodGet, "/api/v1/investigations/"+item.InvestigationID+"/timeline")
		if response.Code != http.StatusOK {
			t.Fatalf("timeline status=%d body=%s", response.Code, response.Body.String())
		}
		var result struct {
			Data store.InvestigationTimeline `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Data
	}
	timeline := readTimeline()
	if timeline.Total != 2 || len(timeline.Items) != 2 {
		t.Fatalf("timeline = %+v", timeline)
	}
	if timeline.Items[0].SourceType != "DEPLOYMENT" || timeline.Items[0].RawReference != "https://ci.example.test/run/1" || !strings.Contains(string(timeline.Items[0].QueryParameters), deploymentResult.Data.ID) {
		t.Fatalf("deployment evidence = %+v", timeline.Items[0])
	}
	if timeline.Items[1].SourceType != "GRAFANA" || timeline.Items[1].RawReference != "https://grafana.example.test/alert/1" || !strings.Contains(string(timeline.Items[1].QueryParameters), item.Alert.ID) {
		t.Fatalf("alert evidence = %+v", timeline.Items[1])
	}
	duplicate := post("/api/v1/alerts/grafana", alertBody+" ", "test-alert-signing-key")
	if duplicate.Code != http.StatusOK {
		t.Fatalf("duplicate status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}
	var duplicateResult struct {
		Data struct {
			Items []store.GrafanaAlertResult `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(duplicate.Body.Bytes(), &duplicateResult); err != nil {
		t.Fatal(err)
	}
	if len(duplicateResult.Data.Items) != 1 || duplicateResult.Data.Items[0].InvestigationID != item.InvestigationID || !duplicateResult.Data.Items[0].Duplicate {
		t.Fatalf("duplicate result = %+v", duplicateResult.Data.Items)
	}
	if timeline = readTimeline(); timeline.Total != 2 {
		t.Fatalf("duplicate created extra evidence: %+v", timeline)
	}
}
