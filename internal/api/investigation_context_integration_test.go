package api

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/store"
)

func TestInvestigationContextReadsCanonicalFactsAndMissingStates(t *testing.T) {
	db := openDiagnosisTestDB(t)
	ctx := context.Background()
	investigationID, serviceID := insertDiagnosisFixture(t, db)
	repository := store.NewPostgres(db)
	handler := NewHandler(repository, discardLogger())
	read := func() map[string]json.RawMessage {
		t.Helper()
		response := serve(handler, http.MethodGet, "/api/v1/investigations/"+investigationID)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		var envelope struct {
			Data map[string]json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		return envelope.Data
	}
	data := read()
	if string(data["investigation_id"]) != `"`+investigationID+`"` || string(data["mapping_status"]) != `"MATCHED"` ||
		string(data["alert"]) != "null" || string(data["completed_at"]) != "null" || string(data["status"]) != `"RECEIVED"` ||
		string(data["environment"]) != `"prod"` || string(data["context_gaps"]) != `["alert_not_linked"]` {
		t.Fatalf("context without alert = %s", mustJSON(t, data))
	}
	var service struct{ ID, Slug, Name string }
	if err := json.Unmarshal(data["service"], &service); err != nil {
		t.Fatal(err)
	}
	if service.ID != serviceID || service.Slug != "checkout-api" || service.Name != "Checkout API" {
		t.Fatalf("service = %+v", service)
	}
	var projectID string
	if err := db.QueryRowContext(ctx, `SELECT project_id::text FROM services WHERE id=$1`, serviceID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)
	alert, _, err := repository.CreateAlert(ctx, store.CreateAlertInput{
		ProjectID: projectID, ServiceID: serviceID, Environment: "prod", Fingerprint: "context-fixture", IdempotencyKey: "context-fixture",
		Status: "FIRING", Severity: "ERROR", Summary: "Latency rose password=synthetic-private-value",
		StartsAt: start, SourceReference: "https://grafana.example.test/alert?token=synthetic-private-query",
		Labels:      json.RawMessage(`{"private-label":"must-not-project","mapping_status":"NEEDS_MAPPING"}`),
		Annotations: json.RawMessage(`{"private-annotation":"must-not-project"}`), RedactedPayload: json.RawMessage(`{"secret_ref":"must-not-project"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE incidents SET alert_id=$1 WHERE id=(SELECT incident_id FROM investigations WHERE id=$2)`, alert.ID, investigationID); err != nil {
		t.Fatal(err)
	}
	data = read()
	var alertView struct {
		ID, Status, Severity, Summary string
		StartsAt                      time.Time  `json:"starts_at"`
		EndsAt                        *time.Time `json:"ends_at"`
	}
	if err := json.Unmarshal(data["alert"], &alertView); err != nil {
		t.Fatal(err)
	}
	if alertView.ID != alert.ID || alertView.Status != "FIRING" || alertView.Severity != "ERROR" ||
		!alertView.StartsAt.Equal(start) || alertView.EndsAt != nil || !strings.Contains(alertView.Summary, redact.RedactedValue) ||
		string(data["mapping_status"]) != `"MATCHED"` || string(data["context_gaps"]) != `[]` {
		t.Fatalf("linked context = %s", mustJSON(t, data))
	}
	for _, private := range []string{"synthetic-private-value", "synthetic-private-query", "must-not-project", "labels", "annotations", "redacted_payload", "secret_ref", "idempotency_key", "fingerprint"} {
		if strings.Contains(string(mustJSON(t, data)), private) {
			t.Fatalf("context leaked %q", private)
		}
	}
	// Reading current state must not freeze the first alert, or resolve the investigation itself.
	if _, err := db.ExecContext(ctx, `UPDATE alerts SET status='RESOLVED', ends_at=$1 WHERE id=$2`, start.Add(time.Minute), alert.ID); err != nil {
		t.Fatal(err)
	}
	data = read()
	if err := json.Unmarshal(data["alert"], &alertView); err != nil || alertView.Status != "RESOLVED" || alertView.EndsAt == nil || string(data["status"]) != `"RECEIVED"` {
		t.Fatalf("resolved alert changed investigation or was stale: %s err=%v", mustJSON(t, data), err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE investigations SET environment=NULL; UPDATE incidents SET environment=NULL; UPDATE alerts SET environment=NULL`); err != nil {
		t.Fatal(err)
	}
	data = read()
	if string(data["mapping_status"]) != `"NEEDS_MAPPING"` || string(data["environment"]) != "null" ||
		string(data["context_gaps"]) != `["environment_mapping_missing"]` || !strings.Contains(string(data["service"]), serviceID) {
		t.Fatalf("service with missing environment = %s", mustJSON(t, data))
	}
	if _, err := db.ExecContext(ctx, `UPDATE investigations SET environment='prod'; UPDATE incidents SET environment='prod'; UPDATE alerts SET environment='prod'`); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name, setup, mapping string
		gaps                 []string
	}{
		{"alert mapping differs", `UPDATE alerts SET environment='staging'`, "CONFLICT", []string{"mapping_conflict"}},
		{"incident mapping differs", `UPDATE alerts SET environment='prod'; UPDATE incidents SET environment='staging'`, "CONFLICT", []string{"mapping_conflict"}},
		{"investigation service differs", `UPDATE incidents SET environment='prod'; UPDATE investigations SET service_id=gen_random_uuid()`, "CONFLICT", []string{"mapping_conflict"}},
		{"all unmapped", `UPDATE investigations SET service_id=NULL, environment=NULL; UPDATE incidents SET service_id=NULL, environment=NULL; UPDATE alerts SET service_id=NULL, environment=NULL`, "NEEDS_MAPPING", []string{"service_mapping_missing", "environment_mapping_missing"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, test.setup); err != nil {
				t.Fatal(err)
			}
			data := read()
			var gaps []string
			if err := json.Unmarshal(data["context_gaps"], &gaps); err != nil {
				t.Fatal(err)
			}
			if string(data["mapping_status"]) != `"`+test.mapping+`"` || !reflect.DeepEqual(gaps, test.gaps) ||
				string(data["service"]) != "null" || string(data["environment"]) != "null" || string(data["alert"]) == "null" {
				t.Fatalf("mapping context = %s", mustJSON(t, data))
			}
		})
	}
	response := serve(handler, http.MethodGet, investigationContextPath)
	assertErrorResponse(t, response, http.StatusNotFound, "not_found")
	if _, err := db.ExecContext(ctx, `DROP TABLE investigations CASCADE`); err != nil {
		t.Fatal(err)
	}
	response = serve(handler, http.MethodGet, "/api/v1/investigations/"+investigationID)
	assertErrorResponse(t, response, http.StatusInternalServerError, "internal_error")
	if strings.Contains(response.Body.String(), "investigations") {
		t.Fatal("internal database details leaked")
	}
}

func TestInvestigationContextHidesCrossProjectService(t *testing.T) {
	db := openDiagnosisTestDB(t)
	ctx := context.Background()
	investigationID, _ := insertDiagnosisFixture(t, db)
	var projectID, otherServiceID string
	if err := db.QueryRowContext(ctx, `INSERT INTO projects (slug, name) VALUES ('other', 'Other') RETURNING id::text`).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO services (project_id, slug, name) VALUES ($1, 'private-service', 'Private service') RETURNING id::text`, projectID).Scan(&otherServiceID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE investigations SET service_id=$1 WHERE id=$2`, otherServiceID, investigationID); err != nil {
		t.Fatal(err)
	}
	response := serve(NewHandler(store.NewPostgres(db), discardLogger()), http.MethodGet, "/api/v1/investigations/"+investigationID)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"mapping_status":"CONFLICT"`) ||
		!strings.Contains(response.Body.String(), `"service":null`) || strings.Contains(response.Body.String(), "Private service") ||
		strings.Contains(response.Body.String(), otherServiceID) {
		t.Fatalf("cross-project context = %d %s", response.Code, response.Body.String())
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
