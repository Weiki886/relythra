package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/security/audit"
	"github.com/Weiki886/relythra/internal/store"
)

const (
	maxGrafanaWebhookBodyBytes  = 1 << 20
	maxGrafanaAlerts            = 100
	maxGrafanaLabels            = 64
	maxGrafanaLabelLength       = 256
	maxGrafanaAnnotationLength  = 4096
	maxGrafanaAnnotationEntries = 64
	maxGrafanaValues            = 64
)

var errInvalidGrafanaWebhook = errors.New("invalid Grafana webhook payload")

type GrafanaWebhook struct {
	Receiver          string                `json:"receiver"`
	Status            string                `json:"status"`
	Alerts            []GrafanaWebhookAlert `json:"alerts"`
	GroupLabels       map[string]string     `json:"groupLabels"`
	CommonLabels      map[string]string     `json:"commonLabels"`
	CommonAnnotations map[string]string     `json:"commonAnnotations"`
	ExternalURL       string                `json:"externalURL"`
	Version           string                `json:"version"`
	GroupKey          string                `json:"groupKey"`
	TruncatedAlerts   int                   `json:"truncatedAlerts"`
	OrgID             int                   `json:"orgId"`
}

type GrafanaWebhookAlert struct {
	Status             string             `json:"status"`
	Labels             map[string]string  `json:"labels"`
	Annotations        map[string]string  `json:"annotations"`
	StartsAt           time.Time          `json:"startsAt"`
	EndsAt             *time.Time         `json:"endsAt"`
	GeneratorURL       string             `json:"generatorURL"`
	SilenceURL         string             `json:"silenceURL"`
	DashboardURL       string             `json:"dashboardURL"`
	PanelURL           string             `json:"panelURL"`
	ValueString        string             `json:"valueString"`
	Values             map[string]float64 `json:"values"`
	Fingerprint        string             `json:"fingerprint"`
	SourceTimezone     string             `json:"-"`
	SourceTimeText     string             `json:"-"`
	ProjectSlug        string             `json:"-"`
	ServiceSlug        string             `json:"-"`
	Environment        string             `json:"-"`
	Severity           string             `json:"-"`
	Summary            string             `json:"-"`
	FingerprintVersion string             `json:"-"`
}

func (alert *GrafanaWebhookAlert) UnmarshalJSON(data []byte) error {
	type wireAlert GrafanaWebhookAlert
	var decoded wireAlert
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errInvalidGrafanaWebhook
	}
	var source struct {
		StartsAt string `json:"startsAt"`
	}
	if err := json.Unmarshal(data, &source); err != nil {
		return err
	}
	if source.StartsAt == "" {
		return errInvalidGrafanaWebhook
	}
	decoded.SourceTimeText = source.StartsAt
	decoded.SourceTimezone = grafanaTimestampTimezone(source.StartsAt)
	*alert = GrafanaWebhookAlert(decoded)
	return nil
}

func grafanaTimestampTimezone(value string) string {
	separator := strings.IndexByte(value, 'T')
	if separator < 0 {
		return ""
	}
	timePart := value[separator+1:]
	if strings.HasSuffix(timePart, "Z") {
		return "UTC"
	}
	for index := len(timePart) - 1; index > 0; index-- {
		if timePart[index] == '+' || timePart[index] == '-' {
			return timePart[index:]
		}
	}
	return ""
}

func ParseGrafanaWebhook(data []byte) (GrafanaWebhook, error) {
	var payload GrafanaWebhook
	if len(data) == 0 || len(data) > maxGrafanaWebhookBodyBytes {
		return GrafanaWebhook{}, errInvalidGrafanaWebhook
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return GrafanaWebhook{}, fmt.Errorf("%w: %v", errInvalidGrafanaWebhook, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return GrafanaWebhook{}, errInvalidGrafanaWebhook
	}
	if len(payload.Alerts) == 0 || len(payload.Alerts) > maxGrafanaAlerts {
		return GrafanaWebhook{}, errInvalidGrafanaWebhook
	}
	if len(payload.GroupLabels) > maxGrafanaLabels || len(payload.CommonLabels) > maxGrafanaLabels ||
		len(payload.CommonAnnotations) > maxGrafanaAnnotationEntries ||
		!validGrafanaStringMapAllowEmpty(payload.GroupLabels, maxGrafanaLabelLength) ||
		!validGrafanaStringMapAllowEmpty(payload.CommonLabels, maxGrafanaLabelLength) ||
		!validGrafanaStringMapAllowEmpty(payload.CommonAnnotations, maxGrafanaAnnotationLength) || len(payload.ExternalURL) > 2048 ||
		len(payload.Receiver) > 256 || len(payload.GroupKey) > 512 || payload.TruncatedAlerts < 0 {
		return GrafanaWebhook{}, errInvalidGrafanaWebhook
	}
	if payload.Status != "firing" && payload.Status != "resolved" && payload.Status != "mixed" && payload.Status != "" {
		return GrafanaWebhook{}, errInvalidGrafanaWebhook
	}
	for index := range payload.Alerts {
		alert := &payload.Alerts[index]
		alert.Labels = mergeGrafanaStringMaps(payload.CommonLabels, alert.Labels)
		alert.Annotations = mergeGrafanaStringMaps(payload.CommonAnnotations, alert.Annotations)
		if !validGrafanaAlertStatus(alert.Status) || alert.StartsAt.IsZero() ||
			len(alert.Labels) > maxGrafanaLabels || !validGrafanaStringMapAllowEmpty(alert.Labels, maxGrafanaLabelLength) ||
			len(alert.Annotations) > maxGrafanaAnnotationEntries || !validGrafanaStringMapAllowEmpty(alert.Annotations, maxGrafanaAnnotationLength) ||
			len(alert.Values) > maxGrafanaValues || len(alert.ValueString) > maxGrafanaAnnotationLength {
			return GrafanaWebhook{}, errInvalidGrafanaWebhook
		}
		for reference := range alert.Values {
			if strings.TrimSpace(reference) == "" || len(reference) > maxGrafanaLabelLength {
				return GrafanaWebhook{}, errInvalidGrafanaWebhook
			}
		}
		if alert.EndsAt != nil && alert.EndsAt.Equal(time.Time{}) {
			alert.EndsAt = nil
		}
		if alert.EndsAt != nil && alert.EndsAt.Before(alert.StartsAt) {
			return GrafanaWebhook{}, errInvalidGrafanaWebhook
		}
		if len(alert.GeneratorURL) > 2048 || len(alert.Fingerprint) > 128 {
			return GrafanaWebhook{}, errInvalidGrafanaWebhook
		}
		if alert.GeneratorURL != "" {
			parsed, err := url.ParseRequestURI(alert.GeneratorURL)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
				return GrafanaWebhook{}, errInvalidGrafanaWebhook
			}
		}
		alert.ProjectSlug = strings.TrimSpace(alert.Labels["project"])
		alert.ServiceSlug = strings.TrimSpace(alert.Labels["service"])
		alert.Environment = strings.TrimSpace(alert.Labels["env"])
		alert.Status = strings.ToUpper(alert.Status)
		alert.Severity = normalizeGrafanaSeverity(alert.Labels["severity"])
		alert.Summary = strings.TrimSpace(alert.Annotations["summary"])
		if alert.Summary == "" {
			alert.Summary = strings.TrimSpace(alert.Labels["alertname"])
		}
		if alert.Summary == "" {
			return GrafanaWebhook{}, errInvalidGrafanaWebhook
		}
		if alert.Fingerprint == "" {
			alert.Fingerprint = deriveGrafanaFingerprint(*alert)
			alert.FingerprintVersion = "sha256-v1"
		} else {
			alert.FingerprintVersion = "grafana-v1"
		}
		alert.StartsAt = alert.StartsAt.UTC()
		if alert.EndsAt != nil {
			ended := alert.EndsAt.UTC()
			alert.EndsAt = &ended
		}
	}
	return payload, nil
}

func validGrafanaAlertStatus(status string) bool {
	return status == "firing" || status == "resolved"
}

func validGrafanaStringMapAllowEmpty(values map[string]string, maxValueLength int) bool {
	for key, value := range values {
		if strings.TrimSpace(key) == "" || len(key) > maxGrafanaLabelLength || len(value) > maxValueLength {
			return false
		}
	}
	return true
}

func mergeGrafanaStringMaps(common, specific map[string]string) map[string]string {
	merged := make(map[string]string, len(common)+len(specific))
	for key, value := range common {
		merged[key] = value
	}
	for key, value := range specific {
		merged[key] = value
	}
	return merged
}

func normalizeGrafanaSeverity(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "INFO", "WARNING", "ERROR", "CRITICAL":
		return strings.ToUpper(strings.TrimSpace(value))
	default:
		return "UNKNOWN"
	}
}

func deriveGrafanaFingerprint(alert GrafanaWebhookAlert) string {
	keys := make([]string, 0, len(alert.Labels))
	for key := range alert.Labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	labels := make(map[string]string, len(keys))
	for _, key := range keys {
		labels[key] = alert.Labels[key]
	}
	identity, _ := json.Marshal(struct {
		Version     string            `json:"version"`
		Project     string            `json:"project"`
		Service     string            `json:"service"`
		Environment string            `json:"environment"`
		StartsAt    string            `json:"starts_at"`
		Labels      map[string]string `json:"labels"`
	}{
		Version: "sha256-v1", Project: alert.ProjectSlug, Service: alert.ServiceSlug,
		Environment: alert.Environment, StartsAt: alert.StartsAt.UTC().Format(time.RFC3339Nano), Labels: labels,
	})
	digest := sha256.Sum256(identity)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (handler *handler) receiveGrafanaWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r, http.MethodPost)
		return
	}
	if handler.grafanaAlerts == nil || handler.auditRecorder == nil || handler.grafanaWebhookSecret == "" {
		writeError(w, r, http.StatusServiceUnavailable, "grafana_webhook_unavailable", "Grafana webhook ingestion is unavailable")
		return
	}
	mediaType, _, mediaTypeErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaTypeErr != nil || !strings.EqualFold(mediaType, "application/json") {
		handler.recordGrafanaWebhookError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", audit.ResultDenied)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxGrafanaWebhookBodyBytes+1))
	if err != nil || len(body) > maxGrafanaWebhookBodyBytes {
		handler.recordGrafanaWebhookError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", audit.ResultDenied)
		return
	}
	timestamp := r.Header.Get("X-Relythra-Timestamp")
	signature := r.Header.Get("X-Relythra-Signature")
	if err := VerifyDeploymentSignature([]byte(handler.grafanaWebhookSecret), timestamp, signature, body, time.Now().UTC()); err != nil {
		handler.recordGrafanaWebhookError(w, r, http.StatusUnauthorized, "invalid_signature", audit.ResultDenied)
		return
	}
	payload, err := ParseGrafanaWebhook(body)
	if err != nil {
		handler.recordGrafanaWebhookError(w, r, http.StatusBadRequest, "invalid_grafana_payload", audit.ResultFailed)
		return
	}
	replayKey, err := DeploymentSignatureReplayKey(signature)
	if err != nil {
		handler.recordGrafanaWebhookError(w, r, http.StatusUnauthorized, "invalid_signature", audit.ResultDenied)
		return
	}
	expiresAt, err := DeploymentSignatureExpiresAt(timestamp)
	if err != nil {
		handler.recordGrafanaWebhookError(w, r, http.StatusUnauthorized, "invalid_signature", audit.ResultDenied)
		return
	}
	claimed, err := handler.grafanaAlerts.ClaimDeploymentWebhookSignature(r.Context(), replayKey, expiresAt)
	if err != nil {
		handler.writeStoreError(w, r, err)
		return
	}
	if !claimed {
		handler.recordGrafanaWebhookError(w, r, http.StatusConflict, "replayed_signature", audit.ResultDenied)
		return
	}
	redactedEnvelope, err := handler.filter.JSON(r.Context(), json.RawMessage(body))
	if err != nil {
		handler.recordGrafanaWebhookError(w, r, http.StatusBadRequest, "invalid_grafana_payload", audit.ResultFailed)
		return
	}
	redactedEnvelopeJSON, err := json.Marshal(redactedEnvelope)
	if err != nil {
		handler.recordGrafanaWebhookError(w, r, http.StatusBadRequest, "invalid_grafana_payload", audit.ResultFailed)
		return
	}
	inputs := make([]store.GrafanaAlertInput, 0, len(payload.Alerts))
	for _, alert := range payload.Alerts {
		labels, err := json.Marshal(alert.Labels)
		if err != nil {
			handler.recordGrafanaWebhookError(w, r, http.StatusBadRequest, "invalid_grafana_payload", audit.ResultFailed)
			return
		}
		redactedLabels, err := handler.filter.JSON(r.Context(), json.RawMessage(labels))
		if err != nil {
			handler.recordGrafanaWebhookError(w, r, http.StatusBadRequest, "invalid_grafana_payload", audit.ResultFailed)
			return
		}
		labels, err = json.Marshal(redactedLabels)
		if err != nil {
			handler.recordGrafanaWebhookError(w, r, http.StatusBadRequest, "invalid_grafana_payload", audit.ResultFailed)
			return
		}
		annotations, err := json.Marshal(alert.Annotations)
		if err != nil {
			handler.recordGrafanaWebhookError(w, r, http.StatusBadRequest, "invalid_grafana_payload", audit.ResultFailed)
			return
		}
		redactedAnnotations, err := handler.filter.JSON(r.Context(), json.RawMessage(annotations))
		if err != nil {
			handler.recordGrafanaWebhookError(w, r, http.StatusBadRequest, "invalid_grafana_payload", audit.ResultFailed)
			return
		}
		annotations, err = json.Marshal(redactedAnnotations)
		if err != nil {
			handler.recordGrafanaWebhookError(w, r, http.StatusBadRequest, "invalid_grafana_payload", audit.ResultFailed)
			return
		}
		inputs = append(inputs, store.GrafanaAlertInput{
			ProjectSlug: alert.ProjectSlug, ServiceSlug: alert.ServiceSlug, Environment: alert.Environment,
			Fingerprint: alert.Fingerprint, FingerprintVersion: alert.FingerprintVersion,
			Status: alert.Status, Severity: alert.Severity, Summary: alert.Summary,
			StartsAt: alert.StartsAt, EndsAt: alert.EndsAt, Labels: labels, Annotations: annotations,
			RedactedPayload: redactedEnvelopeJSON, SourceReference: alert.GeneratorURL,
			SourceTimezone: alert.SourceTimezone, SourceTimeText: alert.SourceTimeText,
		})
	}
	results, err := handler.grafanaAlerts.IngestGrafanaAlerts(r.Context(), inputs, RequestIDFromContext(r.Context()), handler.filter)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			handler.recordGrafanaWebhookError(w, r, http.StatusUnprocessableEntity, "needs_mapping", audit.ResultDenied)
			return
		}
		handler.writeStoreError(w, r, err)
		return
	}
	if err := handler.recordGrafanaWebhookSuccess(r, results); err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "audit_unavailable", "Grafana webhook audit is unavailable")
		return
	}
	status := http.StatusOK
	created := false
	needsMapping := false
	for _, result := range results {
		if result.Created {
			created = true
		}
		if result.MatchState == "NEEDS_MAPPING" {
			needsMapping = true
		}
	}
	if needsMapping {
		status = http.StatusAccepted
	} else if created {
		status = http.StatusCreated
	}
	handler.writeData(w, r, status, map[string]any{"items": results})
}

func (handler *handler) recordGrafanaWebhookError(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	code string,
	result audit.Result,
) {
	if _, err := handler.auditRecorder.Record(r.Context(), audit.Event{
		Actor: "grafana", Action: audit.ActionWebhookReceived, ObjectType: "alert",
		ObjectID: "unverified", Result: result, RequestID: RequestIDFromContext(r.Context()),
		Parameters: map[string]any{"error_code": code}, OccurredAt: time.Now().UTC(),
	}); err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "audit_unavailable", "Grafana webhook audit is unavailable")
		return
	}
	message := "Grafana webhook request was rejected"
	if code == "needs_mapping" {
		message = "Grafana project label does not match a configured project"
	}
	writeError(w, r, status, code, message)
}

func (handler *handler) recordGrafanaWebhookSuccess(r *http.Request, results []store.GrafanaAlertResult) error {
	_, err := handler.auditRecorder.Record(r.Context(), audit.Event{
		Actor: "grafana", Action: audit.ActionWebhookReceived, ObjectType: "alert",
		ObjectID: "batch", Result: audit.ResultSucceeded,
		RequestID: RequestIDFromContext(r.Context()), Parameters: map[string]any{"alert_count": len(results)},
		OccurredAt: time.Now().UTC(),
	})
	return err
}

type grafanaAlertRemapRequest struct {
	ExpectedVersion int64  `json:"expected_version"`
	ServiceID       string `json:"service_id"`
	Environment     string `json:"environment"`
}

func (handler *handler) remapGrafanaAlert(w http.ResponseWriter, r *http.Request) {
	if !handler.authorizeManagement(w, r) {
		return
	}
	handler.withManagementAudit(w, r, func(w http.ResponseWriter, r *http.Request) {
		alertID := r.PathValue("id")
		if state := managementAuditStateFromContext(r); state != nil {
			state.Action = audit.ActionAlertMappingChanged
			state.ObjectType = "alert"
			state.ObjectID = alertID
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r, http.MethodPost)
			return
		}
		if handler.grafanaAlerts == nil {
			writeError(w, r, http.StatusServiceUnavailable, "grafana_webhook_unavailable", "Grafana alert remapping is unavailable")
			return
		}
		if !domain.IsID(alertID) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "alert ID is invalid")
			return
		}
		var request grafanaAlertRemapRequest
		if !decodeStrictJSON(w, r, &request, false) || request.ExpectedVersion < 1 ||
			!domain.IsID(request.ServiceID) || !validDeploymentEnvironment(request.Environment) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "alert remapping request is invalid")
			return
		}
		result, err := handler.grafanaAlerts.RemapGrafanaAlert(r.Context(), alertID, request.ExpectedVersion, request.ServiceID, request.Environment, handler.filter)
		if err != nil {
			handler.writeStoreError(w, r, err)
			return
		}
		handler.writeData(w, r, http.StatusOK, result)
	})
}
