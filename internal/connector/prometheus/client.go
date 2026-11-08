// Package prometheus executes bounded queries from the registered Prometheus
// template catalog. It never accepts a caller-supplied PromQL expression.
package prometheus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/security/outbound"
	"github.com/Weiki886/relythra/internal/security/secrets"
)

const (
	DefaultTimeout     = 8 * time.Second
	MaxResponseBytes   = 4 << 20
	MaxWarnings        = 20
	MaxWarningLength   = 256
	MaxMetricLabels    = 64
	MaxMetricLabelSize = 256
)

var (
	ErrInvalidQuery      = errors.New("invalid Prometheus query")
	ErrPolicyRejected    = errors.New("Prometheus target rejected by outbound policy")
	ErrSecretUnavailable = errors.New("Prometheus credential unavailable")
	ErrTimeout           = errors.New("Prometheus request timed out")
	ErrNetwork           = errors.New("Prometheus request failed")
	ErrUnauthorized      = errors.New("Prometheus denied read access")
	ErrRateLimited       = errors.New("Prometheus rate limited the request")
	ErrRemoteUnavailable = errors.New("Prometheus returned an unsuccessful response")
	ErrInvalidResponse   = errors.New("Prometheus response is invalid")
	ErrResponseTooLarge  = errors.New("Prometheus response exceeds the size limit")
)

type ErrorCategory string

const (
	ErrorInvalidQuery      ErrorCategory = "invalid_query"
	ErrorPolicyRejected    ErrorCategory = "policy_rejected"
	ErrorSecretUnavailable ErrorCategory = "secret_unavailable"
	ErrorTimeout           ErrorCategory = "timeout"
	ErrorNetwork           ErrorCategory = "network_error"
	ErrorUnauthorized      ErrorCategory = "permission_denied"
	ErrorRateLimited       ErrorCategory = "rate_limited"
	ErrorRemoteUnavailable ErrorCategory = "remote_unavailable"
	ErrorInvalidResponse   ErrorCategory = "invalid_response"
	ErrorResponseTooLarge  ErrorCategory = "response_too_large"
)

type QueryError struct {
	Category ErrorCategory
	Cause    error
}

func (err *QueryError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return "Prometheus query failed: " + string(err.Category)
}

func (err *QueryError) Unwrap() error { return err.Cause }

func IsErrorCategory(err error, category ErrorCategory) bool {
	var queryError *QueryError
	return errors.As(err, &queryError) && queryError.Category == category
}

type SecretResolver interface {
	Resolve(context.Context, secrets.Reference) (secrets.Secret, error)
}

type Target struct {
	Endpoint        string
	SecretReference *secrets.Reference
}

type Sample struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

type Series struct {
	Labels  map[string]string `json:"labels"`
	Samples []Sample          `json:"samples"`
}

type Result struct {
	TemplateID      string        `json:"template_id"`
	TemplateVersion int           `json:"template_version"`
	QueryType       string        `json:"query_type"`
	Query           string        `json:"query"`
	Unit            string        `json:"unit"`
	Start           time.Time     `json:"start"`
	End             time.Time     `json:"end"`
	Step            time.Duration `json:"step"`
	Duration        time.Duration `json:"duration"`
	SourceReference string        `json:"source_reference"`
	ResponseSHA256  string        `json:"response_sha256"`
	Series          []Series      `json:"series"`
	Warnings        []string      `json:"warnings"`
	LatestSampleAt  *time.Time    `json:"latest_sample_at,omitempty"`
	Empty           bool          `json:"empty"`
	Partial         bool          `json:"partial"`
	Stale           bool          `json:"stale"`
}

type optionConfig struct {
	timeout time.Duration
}

type Option func(*optionConfig) error

func WithTimeout(timeout time.Duration) Option {
	return func(config *optionConfig) error {
		if timeout <= 0 || timeout > time.Minute {
			return errors.New("timeout must be between 1ns and 1m")
		}
		config.timeout = timeout
		return nil
	}
}

type Connector struct {
	policy   targetPolicy
	resolver SecretResolver
	client   *http.Client
}

type targetPolicy interface {
	Validate(context.Context, string) (outbound.Target, error)
}

func NewConnector(policy *outbound.Policy, resolver SecretResolver, options ...Option) (*Connector, error) {
	if policy == nil || resolver == nil {
		return nil, errors.New("outbound policy and secret resolver are required")
	}
	config := optionConfig{timeout: DefaultTimeout}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("Prometheus connector option is nil")
		}
		if err := option(&config); err != nil {
			return nil, fmt.Errorf("configure Prometheus connector: %w", err)
		}
	}
	client, err := outbound.NewHTTPClient(policy, config.timeout)
	if err != nil {
		return nil, fmt.Errorf("create Prometheus HTTP client: %w", err)
	}
	return &Connector{policy: policy, resolver: resolver, client: client}, nil
}

func (connector *Connector) Query(ctx context.Context, target Target, query datasource.NormalizedQuery) (Result, error) {
	started := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	if connector == nil || connector.policy == nil || connector.client == nil || connector.resolver == nil {
		return Result{}, queryError(ErrorInvalidQuery, errors.New("connector is not configured"))
	}
	expression, unit, err := buildExpression(query)
	if err != nil {
		return Result{}, queryError(ErrorInvalidQuery, err)
	}
	if err := validateNormalizedQuery(query); err != nil {
		return Result{}, queryError(ErrorInvalidQuery, err)
	}
	queryType := query.QueryType
	if queryType == "" {
		queryType = datasource.QueryTypeRange
	}
	endpoint, err := url.Parse(strings.TrimSpace(target.Endpoint))
	if err != nil || endpoint == nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return Result{}, queryError(ErrorPolicyRejected, outbound.ErrInvalidTarget)
	}
	base := strings.TrimRight(endpoint.String(), "/")
	requestPath := "/api/v1/query_range"
	if queryType == datasource.QueryTypeInstant {
		requestPath = "/api/v1/query"
	}
	requestURL := base + requestPath
	if _, err := connector.policy.Validate(ctx, target.Endpoint); err != nil {
		return Result{}, queryError(ErrorPolicyRejected, err)
	}
	values := url.Values{"query": []string{expression}}
	if queryType == datasource.QueryTypeInstant {
		values.Set("time", strconv.FormatFloat(float64(query.End.UnixNano())/float64(time.Second), 'f', 3, 64))
	} else {
		values.Set("start", strconv.FormatFloat(float64(query.Start.UnixNano())/float64(time.Second), 'f', 3, 64))
		values.Set("end", strconv.FormatFloat(float64(query.End.UnixNano())/float64(time.Second), 'f', 3, 64))
		values.Set("step", query.Step.String())
	}
	method := http.MethodPost
	var bodyReader io.Reader = strings.NewReader(values.Encode())
	// The demo gateway permits only GET on fixed read endpoints (ADR 0005).
	if strings.HasPrefix(query.TemplateID, "prometheus.runtime.") {
		method = http.MethodGet
		requestURL += "?" + values.Encode()
		bodyReader = nil
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, bodyReader)
	if err != nil {
		return Result{}, queryError(ErrorInvalidQuery, err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", "Relythra/1.0")
	if target.SecretReference != nil {
		secret, err := connector.resolver.Resolve(ctx, *target.SecretReference)
		if err != nil {
			return Result{}, queryError(ErrorSecretUnavailable, err)
		}
		request.Header.Set("Authorization", "Bearer "+secret.Reveal())
	}
	response, err := connector.client.Do(request)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			return Result{}, queryError(ErrorTimeout, err)
		}
		if errors.Is(err, outbound.ErrRedirectBlocked) || errors.Is(err, outbound.ErrUnsafeAddress) ||
			errors.Is(err, outbound.ErrHostNotAllowed) || errors.Is(err, outbound.ErrPortNotAllowed) ||
			errors.Is(err, outbound.ErrSchemeNotAllowed) || errors.Is(err, outbound.ErrResolutionFailed) {
			return Result{}, queryError(ErrorPolicyRejected, err)
		}
		return Result{}, queryError(ErrorNetwork, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil {
		return Result{}, classifyReadError(err)
	}
	if len(body) > MaxResponseBytes {
		return Result{}, queryError(ErrorResponseTooLarge, ErrResponseTooLarge)
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return Result{}, queryError(ErrorUnauthorized, ErrUnauthorized)
	case response.StatusCode == http.StatusTooManyRequests:
		return Result{}, queryError(ErrorRateLimited, ErrRateLimited)
	case response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices:
		return Result{}, queryError(ErrorRemoteUnavailable, fmt.Errorf("HTTP status %d", response.StatusCode))
	}
	parsed, err := parseResponse(body, queryType)
	if err != nil {
		return Result{}, queryError(ErrorInvalidResponse, err)
	}
	digest := sha256.Sum256(body)
	result := Result{
		TemplateID: query.TemplateID, TemplateVersion: query.Version, QueryType: queryType, Query: expression, Unit: unit,
		Start: query.Start, End: query.End, Step: query.Step, Duration: time.Since(started),
		SourceReference: requestURL, ResponseSHA256: hex.EncodeToString(digest[:]),
		Series:   make([]Series, 0, min(len(parsed.Data.Result), query.MaxSeries)),
		Warnings: cleanWarnings(parsed.Warnings),
	}
	if len(result.Warnings) > 0 {
		result.Partial = true
	}
	totalPoints := 0
	allSeriesStale := true
	staleAfter := max(2*query.Step, 2*time.Minute)
	for index, rawSeries := range parsed.Data.Result {
		if index >= query.MaxSeries {
			result.Partial = true
			addWarning(&result.Warnings, "result exceeded the requested series limit")
			break
		}
		series, err := parseSeries(rawSeries, query.MaxPoints)
		if err != nil {
			result.Partial = true
			addWarning(&result.Warnings, "one or more series could not be parsed")
			continue
		}
		if len(series.Samples) == 0 {
			result.Partial = true
			addWarning(&result.Warnings, "one or more series had no valid samples")
			continue
		}
		if totalPoints+len(series.Samples) > datasource.MaxQueryTotalPoints {
			remaining := datasource.MaxQueryTotalPoints - totalPoints
			if remaining <= 0 {
				result.Partial = true
				addWarning(&result.Warnings, "result exceeded the total sample limit")
				break
			}
			series.Samples = series.Samples[:remaining]
			result.Partial = true
			addWarning(&result.Warnings, "result was truncated at the total sample limit")
		}
		if len(series.Samples) == query.MaxPoints && len(rawSeries.Values) > query.MaxPoints {
			result.Partial = true
			addWarning(&result.Warnings, "one or more series exceeded the requested point limit")
		}
		totalPoints += len(series.Samples)
		latest := series.Samples[len(series.Samples)-1].Timestamp
		if result.LatestSampleAt == nil || latest.After(*result.LatestSampleAt) {
			result.LatestSampleAt = &latest
		}
		if query.End.Sub(latest) <= staleAfter {
			allSeriesStale = false
		}
		result.Series = append(result.Series, series)
	}
	result.Empty = len(result.Series) == 0
	result.Stale = !result.Empty && allSeriesStale
	return result, nil
}

type responseEnvelope struct {
	Status   string   `json:"status"`
	Error    string   `json:"error"`
	Warnings []string `json:"warnings"`
	Data     struct {
		ResultType string      `json:"resultType"`
		Result     []rawSeries `json:"result"`
	} `json:"data"`
}

type rawSeries struct {
	Metric map[string]any      `json:"metric"`
	Values [][]json.RawMessage `json:"values"`
	Value  []json.RawMessage   `json:"value"`
}

func parseResponse(body []byte, queryType string) (responseEnvelope, error) {
	var response responseEnvelope
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := decoder.Decode(&response); err != nil {
		return responseEnvelope{}, errors.New("response is not valid JSON")
	}
	if response.Status != "success" {
		return responseEnvelope{}, errors.New("Prometheus API response status is not success")
	}
	expectedType := "matrix"
	if queryType == datasource.QueryTypeInstant {
		expectedType = "vector"
		for index := range response.Data.Result {
			response.Data.Result[index].Values = [][]json.RawMessage{response.Data.Result[index].Value}
		}
	}
	if response.Data.ResultType != expectedType {
		return responseEnvelope{}, errors.New("Prometheus response type does not match the query")
	}
	return response, nil
}

func parseSeries(raw rawSeries, maxPoints int) (Series, error) {
	if len(raw.Metric) == 0 || len(raw.Metric) > MaxMetricLabels {
		return Series{}, errors.New("metric labels are outside bounds")
	}
	labels := make(map[string]string, len(raw.Metric))
	for key, value := range raw.Metric {
		text, ok := value.(string)
		if !ok || strings.TrimSpace(key) == "" || len(key) > MaxMetricLabelSize || len(text) > MaxMetricLabelSize {
			return Series{}, errors.New("metric label is invalid")
		}
		labels[key] = text
	}
	series := Series{Labels: labels, Samples: make([]Sample, 0, min(len(raw.Values), maxPoints))}
	for _, pair := range raw.Values {
		if len(pair) != 2 {
			continue
		}
		var timestampValue, sampleValue string
		if err := json.Unmarshal(pair[0], &timestampValue); err != nil {
			timestampValue = string(pair[0])
		}
		if err := json.Unmarshal(pair[1], &sampleValue); err != nil {
			return Series{}, errors.New("sample value is invalid")
		}
		timestamp, err := strconv.ParseFloat(timestampValue, 64)
		if err != nil || math.IsNaN(timestamp) || math.IsInf(timestamp, 0) {
			continue
		}
		value, err := strconv.ParseFloat(sampleValue, 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		nanoseconds := int64(timestamp * float64(time.Second))
		series.Samples = append(series.Samples, Sample{Timestamp: time.Unix(0, nanoseconds).UTC(), Value: value})
	}
	sort.Slice(series.Samples, func(left, right int) bool {
		return series.Samples[left].Timestamp.Before(series.Samples[right].Timestamp)
	})
	if len(series.Samples) > maxPoints {
		series.Samples = series.Samples[:maxPoints]
	}
	return series, nil
}

func buildExpression(query datasource.NormalizedQuery) (string, string, error) {
	if query.TemplateID == "" || query.Version != 1 {
		return "", "", errors.New("template ID or version is invalid")
	}
	service, environment := strconv.Quote(query.Service), strconv.Quote(query.Environment)
	selector := "service=" + service + ",env=" + environment
	switch query.TemplateID {
	case "prometheus.service.latency.v1":
		return "histogram_quantile(0.95, sum by (le, route) (rate(demo_http_request_duration_seconds_bucket{" + selector + "}[5m])))", "seconds", nil
	case "prometheus.service.error_ratio.v1":
		all := "sum by (route) (rate(demo_http_requests_total{" + selector + "}[5m]))"
		failures := "sum by (route) (rate(demo_http_requests_total{" + selector + ",status=~\"5..\"}[5m]))"
		return failures + " / clamp_min(" + all + ", 1e-12)", "ratio", nil
	case "prometheus.service.request_rate.v1":
		return "sum by (route) (rate(demo_http_requests_total{" + selector + "}[5m]))", "requests_per_second", nil
	case "prometheus.container.cpu.v1":
		return "sum by (container) (rate(container_cpu_usage_seconds_total{" + selector + "}[5m]))", "cores", nil
	case "prometheus.container.memory.v1":
		return "sum by (container) (container_memory_working_set_bytes{" + selector + "})", "bytes", nil
	case "prometheus.database.query_latency.v1":
		return "histogram_quantile(0.95, sum by (le, operation) (rate(db_client_query_duration_seconds_bucket{" + selector + "}[5m])))", "seconds", nil
	case "prometheus.node.capacity.v1":
		return "node_memory_MemAvailable_bytes{" + selector + "}", "bytes", nil
	case "prometheus.runtime.container.cpu.v1":
		return "sum by (id, host_id, mapping_status, container_label_com_docker_compose_service) (rate(container_cpu_usage_seconds_total{" + selector + "}[5m]))", "cores", nil
	case "prometheus.runtime.container.memory.v1":
		return "sum by (id, host_id, mapping_status, container_label_com_docker_compose_service) (container_memory_working_set_bytes{" + selector + "})", "bytes", nil
	case "prometheus.runtime.container.oom_events.v1":
		return "sum by (id, host_id, mapping_status, container_label_com_docker_compose_service) (increase(container_oom_events_total{" + selector + "}[5m]))", "events", nil
	case "prometheus.runtime.container.start_time.v1":
		return "max by (id, host_id, mapping_status, container_label_com_docker_compose_service) (container_start_time_seconds{" + selector + "})", "unix_seconds", nil
	case "prometheus.runtime.host.cpu.v1":
		return "sum by (host_id, instance) (rate(node_cpu_seconds_total{" + selector + ",mode!=\"idle\"}[5m]))", "cores", nil
	case "prometheus.runtime.host.memory_available.v1":
		return "max by (host_id, instance) (node_memory_MemAvailable_bytes{" + selector + "})", "bytes", nil
	case "prometheus.runtime.host.load.v1":
		return "max by (host_id, instance) (node_load1{" + selector + "})", "load_average", nil
	default:
		return "", "", errors.New("template is not registered for Prometheus execution")
	}
}

func validateNormalizedQuery(query datasource.NormalizedQuery) error {
	templates, issues := datasource.ResolveTemplates(datasource.SourcePrometheus, []string{query.TemplateID})
	if len(issues) != 0 || len(templates) != 1 || templates[0].Version != query.Version {
		return errors.New("template is not registered for Prometheus")
	}
	queryType := query.QueryType
	if queryType == "" {
		queryType = datasource.QueryTypeRange
	}
	parameters := datasource.QueryParameters{
		Service: query.Service, Environment: query.Environment,
		QueryType: queryType,
		MaxSeries: query.MaxSeries, MaxPoints: query.MaxPoints,
	}
	if queryType == datasource.QueryTypeInstant {
		parameters.At = query.End.Format(time.RFC3339Nano)
	} else {
		parameters.Start = query.Start.Format(time.RFC3339Nano)
		parameters.End = query.End.Format(time.RFC3339Nano)
		parameters.Step = query.Step.String()
	}
	_, issues = datasource.ValidateQuery(templates[0], parameters)
	if len(issues) != 0 {
		return errors.New("normalized query exceeds the registered template budget")
	}
	return nil
}

func cleanWarnings(warnings []string) []string {
	cleaned := make([]string, 0, min(len(warnings), MaxWarnings))
	for _, warning := range warnings {
		addWarning(&cleaned, warning)
	}
	return cleaned
}

func addWarning(warnings *[]string, warning string) {
	if len(*warnings) >= MaxWarnings {
		return
	}
	warning = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, strings.TrimSpace(warning))
	if len(warning) > MaxWarningLength {
		warning = warning[:MaxWarningLength]
	}
	if warning != "" {
		*warnings = append(*warnings, warning)
	}
}

func classifyReadError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return queryError(ErrorTimeout, err)
	}
	return queryError(ErrorNetwork, err)
}

type timeoutError interface{ Timeout() bool }

func isTimeout(err error) bool {
	var timeout timeoutError
	return errors.As(err, &timeout) && timeout.Timeout()
}

func queryError(category ErrorCategory, cause error) error {
	return &QueryError{Category: category, Cause: cause}
}
