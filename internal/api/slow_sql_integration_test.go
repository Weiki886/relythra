package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/connector/github"
	"github.com/Weiki886/relythra/internal/connector/loki"
	"github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/diagnosis"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/security/secrets"
	"github.com/Weiki886/relythra/internal/store"
)

// This integration test composes the existing public deployment and Grafana
// ingestion paths with controlled connector snapshots and the read-only
// diagnosis/timeline APIs. It does not assert that webhook receipt schedules
// connector collection.
func TestSlowSQLDeploymentAlertEvidenceDiagnosisTimelineIntegration(t *testing.T) {
	db := openDiagnosisTestDB(t)
	ctx := context.Background()
	var projectID, serviceID, releaseID string
	const commitSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := db.QueryRowContext(ctx, `INSERT INTO projects (slug, name) VALUES ('slow-sql-demo', 'Slow SQL Demo') RETURNING id::text`).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO services (project_id, slug, name) VALUES ($1, 'checkout-api', 'Checkout API') RETURNING id::text`, projectID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO releases (project_id, service_id, version, commit_sha) VALUES ($1, $2, 'v1', $3) RETURNING id::text`, projectID, serviceID, commitSHA).Scan(&releaseID); err != nil {
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

	requestTime := strconv.FormatInt(time.Now().Unix(), 10)
	postSigned := func(path, body, key string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Relythra-Timestamp", requestTime)
		request.Header.Set("X-Relythra-Signature", SignDeploymentRequest([]byte(key), requestTime, []byte(body)))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	start := time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)
	deploymentBody := fmt.Sprintf(`{"external_deployment_id":"slow-sql-release-1","project_id":%q,"service_id":%q,"release_id":%q,"environment":"demo","status":"SUCCEEDED","started_at":%q,"finished_at":%q,"version":"v1","commit_sha":%q,"instance_count":1,"source_reference":"https://ci.example.test/runs/slow-sql-1","source_timezone":"UTC","source_time_text":"2026-11-18T01:59:00Z/2026-11-18T02:00:00Z","metadata":{}}`,
		projectID, serviceID, releaseID, start.Add(-time.Minute).Format(time.RFC3339), start.Format(time.RFC3339), commitSHA)
	deploymentResponse := postSigned("/api/v1/deployment-events/webhook", deploymentBody, "test-deployment-signing-key")
	if deploymentResponse.Code != http.StatusCreated {
		t.Fatalf("deployment webhook status=%d body=%s", deploymentResponse.Code, deploymentResponse.Body.String())
	}
	var deploymentEnvelope struct {
		Data store.DeploymentEvent `json:"data"`
	}
	if err := json.Unmarshal(deploymentResponse.Body.Bytes(), &deploymentEnvelope); err != nil {
		t.Fatal(err)
	}
	deployment := deploymentEnvelope.Data
	if deployment.ID == "" || deployment.CommitSHA != commitSHA {
		t.Fatalf("deployment response=%+v", deployment)
	}

	alertBody := `{"receiver":"relythra","status":"firing","alerts":[{"status":"firing","fingerprint":"slow-sql-alert-1","labels":{"project":"slow-sql-demo","service":"checkout-api","env":"demo","alertname":"DatabaseLatency"},"annotations":{"summary":"Checkout database latency is elevated"},"startsAt":"2026-11-18T02:02:00Z","generatorURL":"https://grafana.example.test/alert/slow-sql-1"}]}`
	alertResponse := postSigned("/api/v1/alerts/grafana", alertBody, "test-alert-signing-key")
	if alertResponse.Code != http.StatusCreated {
		t.Fatalf("Grafana webhook status=%d body=%s", alertResponse.Code, alertResponse.Body.String())
	}
	var alertEnvelope struct {
		Data struct {
			Items []store.GrafanaAlertResult `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(alertResponse.Body.Bytes(), &alertEnvelope); err != nil {
		t.Fatal(err)
	}
	if len(alertEnvelope.Data.Items) != 1 {
		t.Fatalf("Grafana webhook items=%+v", alertEnvelope.Data.Items)
	}
	alertResult := alertEnvelope.Data.Items[0]
	if alertResult.InvestigationID == "" || alertResult.MatchState != "MATCHED" || alertResult.DeploymentCount != 1 {
		t.Fatalf("alert/deployment association=%+v", alertResult)
	}

	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	collectedAt := start.Add(6 * time.Minute)
	metric := prometheus.Result{
		TemplateID: "prometheus.database.query_latency.v1", TemplateVersion: 1,
		QueryType: "range", Query: "private_slow_sql_latency_query", Unit: "seconds",
		Start: start, End: start.Add(5 * time.Minute), Step: time.Minute,
		SourceReference: "https://prometheus.example.test/graph?g0.expr=slow-sql",
		Series:          []prometheus.Series{{Labels: map[string]string{"service": "checkout-api", "query": "checkout"}, Samples: []prometheus.Sample{{Timestamp: start.Add(3 * time.Minute), Value: 0.8}}}},
	}
	metricEvidence, created, err := repository.PersistPrometheusEvidence(ctx, metric, evidence.PrometheusEvidenceContext{
		InvestigationID: alertResult.InvestigationID, EntityType: "SERVICE", EntityID: serviceID, CollectedAt: collectedAt,
	}, filter)
	if err != nil || !created {
		t.Fatalf("persist Prometheus evidence: created=%v err=%v", created, err)
	}
	logs := loki.Result{
		TemplateID: "loki.service.slow_queries.v1", TemplateVersion: 1,
		Query: `{service="checkout-api", env="demo"} |= "slow"`, Direction: "backward", Limit: 100,
		Start: start, End: metric.End, SourceReference: "https://loki.example.test/explore?slow-sql",
		Entries: []loki.Entry{{Timestamp: start.Add(4 * time.Minute), Labels: map[string]string{"service": "checkout-api", "env": "demo"}, Line: redact.UntrustedData{
			Trust: "untrusted_data", Source: "loki", Content: "private_slow_sql_statement exceeded threshold", OriginalBytes: len("private_slow_sql_statement exceeded threshold"),
		}}},
	}
	logEvidence, created, err := repository.PersistLokiEvidence(ctx, logs, evidence.LokiEvidenceContext{
		InvestigationID: alertResult.InvestigationID, EntityType: "SERVICE", EntityID: serviceID, CollectedAt: collectedAt,
	}, filter)
	if err != nil || !created {
		t.Fatalf("persist Loki evidence: created=%v err=%v", created, err)
	}

	githubDiff := redact.UntrustedData{Trust: "untrusted_data", Source: "github", Content: "diff --git a/query.sql b/query.sql", OriginalBytes: len("diff --git a/query.sql b/query.sql")}
	_, created, err = repository.PersistGitHubEvidence(ctx, github.Result{
		CommitSHA: commitSHA, DeploymentEventID: deployment.ID,
		Message:    redact.UntrustedData{Trust: "untrusted_data", Source: "github", Content: "slow query index change", OriginalBytes: len("slow query index change")},
		AuthorDate: start.Add(-time.Hour), SourceReference: "https://github.example.test/commit/" + commitSHA,
		ResponseSHA256: strings.Repeat("c", 64), DiffSHA256: strings.Repeat("d", 64),
		ChangedFiles: []github.ChangedFile{{Filename: "query.sql", Status: "modified", Additions: 2, Deletions: 1}},
		OmittedFiles: []string{}, PullRequests: []github.PullRequest{}, DependencyFiles: []github.DependencyFile{},
		Diff: &githubDiff, Warnings: []string{},
	}, evidence.GitHubEvidenceContext{InvestigationID: alertResult.InvestigationID, CollectedAt: collectedAt}, filter)
	if err != nil || !created {
		t.Fatalf("persist deployment-linked GitHub evidence: created=%v err=%v", created, err)
	}

	diagnosisResponse := serve(handler, http.MethodGet, "/api/v1/investigations/"+alertResult.InvestigationID+"/diagnosis")
	if diagnosisResponse.Code != http.StatusOK {
		t.Fatalf("diagnosis status=%d body=%s", diagnosisResponse.Code, diagnosisResponse.Body.String())
	}
	var diagnosisEnvelope struct {
		Data investigationDiagnosis `json:"data"`
	}
	if err := json.Unmarshal(diagnosisResponse.Body.Bytes(), &diagnosisEnvelope); err != nil {
		t.Fatal(err)
	}
	result := diagnosisEnvelope.Data
	if result.InvestigationID != alertResult.InvestigationID || result.EvidenceTotal != 5 || result.EvidenceTruncated ||
		result.Status != diagnosis.StatusCandidatesFound || len(result.Candidates) != 1 {
		t.Fatalf("diagnosis response=%+v", result)
	}
	candidate := result.Candidates[0]
	if candidate.RuleID != diagnosis.RuleSlowQueryLatency || candidate.EntityID != serviceID || candidate.Confidence != diagnosis.ConfidenceMedium ||
		!sameSortedStrings(candidate.SupportEvidenceIDs, []string{metricEvidence.ID, logEvidence.ID}) || len(candidate.ContradictEvidenceIDs) != 0 {
		t.Fatalf("slow SQL candidate=%+v", candidate)
	}
	for _, private := range []string{metric.Query, "private_slow_sql_statement", githubDiff.Content, metric.SourceReference, logs.SourceReference} {
		if strings.Contains(diagnosisResponse.Body.String(), private) {
			t.Fatalf("diagnosis leaked %q", private)
		}
	}

	timelineResponse := serve(handler, http.MethodGet, "/api/v1/investigations/"+alertResult.InvestigationID+"/timeline")
	if timelineResponse.Code != http.StatusOK {
		t.Fatalf("timeline status=%d body=%s", timelineResponse.Code, timelineResponse.Body.String())
	}
	var timelineEnvelope struct {
		Data store.InvestigationTimeline `json:"data"`
	}
	if err := json.Unmarshal(timelineResponse.Body.Bytes(), &timelineEnvelope); err != nil {
		t.Fatal(err)
	}
	timeline := timelineEnvelope.Data
	if timeline.InvestigationID != alertResult.InvestigationID || timeline.Total != 5 || len(timeline.Items) != 5 {
		t.Fatalf("timeline metadata/items=%+v", timeline)
	}
	bySource := make(map[string]store.InvestigationTimelineItem, len(timeline.Items))
	for _, item := range timeline.Items {
		bySource[item.SourceType] = item
	}
	for source, wantReference := range map[string]string{
		"DEPLOYMENT": "https://ci.example.test/runs/slow-sql-1",
		"GRAFANA":    "https://grafana.example.test/alert/slow-sql-1",
		"GITHUB":     "https://github.example.test/commit/" + commitSHA,
		"PROMETHEUS": metric.SourceReference,
		"LOKI":       logs.SourceReference,
	} {
		item, ok := bySource[source]
		if !ok || item.RawReference != wantReference {
			t.Errorf("timeline %s evidence=%+v, want source reference %q", source, item, wantReference)
		}
	}
}

func sameSortedStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	left, right := append([]string(nil), got...), append([]string(nil), want...)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}
