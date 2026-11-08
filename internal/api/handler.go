package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/security/audit"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/store"
)

type Reader interface {
	GetReport(context.Context, string) (store.Report, error)
	GetEvidence(context.Context, string) (store.Evidence, error)
	GetInvestigationTimeline(
		context.Context,
		string,
		store.InvestigationTimelineFilter,
		int,
		int,
	) (store.InvestigationTimeline, error)
	GetDeploymentEvent(context.Context, string) (store.DeploymentEvent, error)
}

type handler struct {
	reader                  Reader
	mappings                MappingRepository
	deployments             DeploymentRepository
	adminAuthenticator      AdminAuthenticator
	connectionTester        ConnectionTester
	auditRecorder           audit.Recorder
	deploymentWebhookSecret string
	deploymentWebhookSource string
	grafanaWebhookSecret    string
	grafanaAlerts           store.GrafanaAlertRepository
	managementActor         string
	logger                  *slog.Logger
	filter                  *redact.Filter
}

func NewHandler(reader Reader, logger *slog.Logger, filters ...*redact.Filter) http.Handler {
	return NewHandlerWithDependencies(
		Dependencies{
			Reader:             reader,
			AdminAuthenticator: ManagementUnavailableAuthenticator{},
		},
		logger,
		filters...,
	)
}

func NewHandlerWithDependencies(
	dependencies Dependencies,
	logger *slog.Logger,
	filters ...*redact.Filter,
) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	filter := defaultRedactionFilter()
	if len(filters) > 0 && filters[0] != nil {
		filter = filters[0]
	}
	if dependencies.AdminAuthenticator == nil {
		dependencies.AdminAuthenticator = ManagementUnavailableAuthenticator{}
	}
	if dependencies.ManagementActor == "" {
		dependencies.ManagementActor = "management-token"
	}
	apiHandler := &handler{
		reader:                  dependencies.Reader,
		mappings:                dependencies.Mappings,
		deployments:             dependencies.Deployments,
		adminAuthenticator:      dependencies.AdminAuthenticator,
		connectionTester:        dependencies.ConnectionTester,
		auditRecorder:           dependencies.AuditRecorder,
		deploymentWebhookSecret: dependencies.DeploymentWebhookSecret.Reveal(),
		deploymentWebhookSource: dependencies.DeploymentWebhookSource,
		grafanaWebhookSecret:    dependencies.GrafanaWebhookSecret.Reveal(),
		grafanaAlerts:           dependencies.GrafanaAlerts,
		managementActor:         dependencies.ManagementActor,
		logger:                  logger,
		filter:                  filter,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/reports/{id}", apiHandler.getReport)
	mux.HandleFunc("/api/v1/evidence/{id}", apiHandler.getEvidence)
	mux.HandleFunc("/api/v1/investigations/{id}/timeline", apiHandler.getInvestigationTimeline)
	mux.HandleFunc("/api/v1/deployments/{id}", apiHandler.getDeployment)
	mux.HandleFunc("/api/v1/deployment-events/webhook", apiHandler.receiveDeploymentWebhook)
	mux.HandleFunc("/api/v1/deployment-events", apiHandler.manageDeploymentCollection)
	mux.HandleFunc("/api/v1/deployment-events/candidates", apiHandler.getDeploymentCandidates)
	mux.HandleFunc("/api/v1/deployment-events/{id}", apiHandler.manageDeploymentItem)
	mux.HandleFunc("/api/v1/alerts/grafana", apiHandler.receiveGrafanaWebhook)
	mux.HandleFunc("/api/v1/alerts/{id}/remap", apiHandler.remapGrafanaAlert)
	mux.HandleFunc("/api/v1/data-source-mappings", apiHandler.manageMappingCollection)
	mux.HandleFunc("/api/v1/data-source-mappings/{id}", apiHandler.manageMappingItem)
	mux.HandleFunc("/api/v1/data-source-mappings/{id}/{action}", apiHandler.manageMappingAction)
	mux.HandleFunc("/api/v1/", apiHandler.notFound)
	return WithRequestID(mux, filter)
}

func defaultRedactionFilter() *redact.Filter {
	filter, err := redact.NewFilter()
	if err != nil {
		panic("initialize API redaction filter: " + err.Error())
	}
	return filter
}

func (handler *handler) getReport(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := requireID(w, r)
	if !ok {
		return
	}
	report, err := handler.reader.GetReport(r.Context(), id)
	if err != nil {
		handler.writeStoreError(w, r, err)
		return
	}
	handler.writeData(w, r, http.StatusOK, report)
}

func (handler *handler) getEvidence(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := requireID(w, r)
	if !ok {
		return
	}
	evidence, err := handler.reader.GetEvidence(r.Context(), id)
	if err != nil {
		handler.writeStoreError(w, r, err)
		return
	}
	handler.writeData(w, r, http.StatusOK, evidence)
}

func (handler *handler) getDeployment(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := requireID(w, r)
	if !ok {
		return
	}
	deployment, err := handler.reader.GetDeploymentEvent(r.Context(), id)
	if err != nil {
		handler.writeStoreError(w, r, err)
		return
	}
	handler.writeData(w, r, http.StatusOK, deployment)
}

func (handler *handler) notFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotFound, "not_found", "resource was not found")
}

func (handler *handler) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrInvalidInput):
		writeError(w, r, http.StatusBadRequest, "invalid_request", "request is invalid")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "not_found", "resource was not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, r, http.StatusConflict, "conflict", "resource changed; retry the request")
	case errors.Is(err, store.ErrInvalidTransition):
		writeError(w, r, http.StatusConflict, "invalid_transition", "deployment state transition is invalid")
	default:
		safeError, redactErr := handler.filter.Text(r.Context(), err.Error())
		if redactErr != nil {
			safeError = "[REDACTION_FAILED]"
		}
		safePath, pathErr := handler.filter.Text(r.Context(), r.URL.Path)
		if pathErr != nil {
			safePath = "[REDACTION_FAILED]"
		}
		handler.logger.ErrorContext(
			r.Context(),
			"domain read failed",
			"request_id", RequestIDFromContext(r.Context()),
			"path", safePath,
			"error", safeError,
		)
		writeError(
			w,
			r,
			http.StatusInternalServerError,
			"internal_error",
			"an internal error occurred",
		)
	}
}

func (handler *handler) writeData(w http.ResponseWriter, r *http.Request, status int, data any) {
	redacted, err := handler.filter.JSON(r.Context(), data)
	if err != nil {
		handler.logger.ErrorContext(
			r.Context(),
			"response redaction failed",
			"request_id", RequestIDFromContext(r.Context()),
			"error_code", "redaction_failed",
		)
		writeError(
			w,
			r,
			http.StatusInternalServerError,
			"internal_error",
			"an internal error occurred",
		)
		return
	}
	if err := writeJSON(w, status, successEnvelope{
		Data:      redacted,
		RequestID: RequestIDFromContext(r.Context()),
	}); err != nil {
		handler.logger.ErrorContext(
			r.Context(),
			"response encoding failed",
			"request_id", RequestIDFromContext(r.Context()),
			"error_code", "encoding_failed",
		)
	}
}

func requireGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	w.Header().Set("Allow", http.MethodGet)
	writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method is not allowed")
	return false
}

func requireID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !domain.IsID(id) {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "resource ID is invalid")
		return "", false
	}
	return id, true
}
