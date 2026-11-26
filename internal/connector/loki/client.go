// Package loki executes bounded queries from the registered Loki template catalog.
// It never accepts a caller-supplied LogQL expression.
package loki

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/security/outbound"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/security/secrets"
)

const (
	DefaultTimeout      = 8 * time.Second
	MaxResponseBytes    = 4 << 20
	MaxQueryEntries     = 1000
	MaxLogLineBytes     = 16 * 1024
	MaxLogLabels        = 64
	MaxLogLabelBytes    = 256
	MaxWarnings         = 20
	MaxWarningLength    = 256
	maxCursorBytes      = 512
	maxAllowedClockSkew = 5 * time.Minute
)

var (
	ErrInvalidQuery      = errors.New("invalid Loki query")
	ErrPolicyRejected    = errors.New("Loki target rejected by outbound policy")
	ErrSecretUnavailable = errors.New("Loki credential unavailable")
	ErrTimeout           = errors.New("Loki request timed out")
	ErrNetwork           = errors.New("Loki request failed")
	ErrUnauthorized      = errors.New("Loki denied read access")
	ErrRateLimited       = errors.New("Loki rate limited the request")
	ErrRemoteUnavailable = errors.New("Loki returned an unsuccessful response")
	ErrInvalidResponse   = errors.New("Loki response is invalid")
	ErrResponseTooLarge  = errors.New("Loki response exceeds the size limit")
	ErrInvalidCursor     = errors.New("Loki pagination cursor is invalid")
	ErrCursorExpired     = errors.New("Loki pagination cursor has expired")
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
	ErrorInvalidCursor     ErrorCategory = "invalid_cursor"
	ErrorCursorExpired     ErrorCategory = "cursor_expired"
)

type QueryError struct {
	Category ErrorCategory
	Cause    error
}

func (err *QueryError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return "Loki query failed: " + string(err.Category)
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
	ResolvedSecret  *secrets.Secret
}

type Entry struct {
	Timestamp         time.Time            `json:"timestamp"`
	SourceTimestamp   string               `json:"source_timestamp"`
	Labels            map[string]string    `json:"labels"`
	Line              redact.UntrustedData `json:"line"`
	OutsideTimeWindow bool                 `json:"outside_time_window,omitempty"`
}

type Result struct {
	TemplateID      string        `json:"template_id"`
	TemplateVersion int           `json:"template_version"`
	Query           string        `json:"query"`
	Start           time.Time     `json:"start"`
	End             time.Time     `json:"end"`
	Direction       string        `json:"direction"`
	Severity        string        `json:"severity,omitempty"`
	Limit           int           `json:"limit"`
	Duration        time.Duration `json:"duration"`
	SourceReference string        `json:"source_reference"`
	ResponseSHA256  string        `json:"response_sha256"`
	Entries         []Entry       `json:"entries"`
	Warnings        []string      `json:"warnings"`
	NextCursor      string        `json:"next_cursor,omitempty"`
	Empty           bool          `json:"empty"`
	Partial         bool          `json:"partial"`
	TimeSkew        bool          `json:"time_skew"`
}

type optionConfig struct{ timeout time.Duration }
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

type targetPolicy interface {
	Validate(context.Context, string) (outbound.Target, error)
}

type Connector struct {
	policy   targetPolicy
	resolver SecretResolver
	filter   *redact.Filter
	client   *http.Client
}

func NewConnector(policy *outbound.Policy, resolver SecretResolver, filter *redact.Filter, options ...Option) (*Connector, error) {
	if policy == nil || resolver == nil || filter == nil {
		return nil, errors.New("outbound policy, secret resolver, and redaction filter are required")
	}
	config := optionConfig{timeout: DefaultTimeout}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("Loki connector option is nil")
		}
		if err := option(&config); err != nil {
			return nil, fmt.Errorf("configure Loki connector: %w", err)
		}
	}
	client, err := outbound.NewHTTPClient(policy, config.timeout)
	if err != nil {
		return nil, fmt.Errorf("create Loki HTTP client: %w", err)
	}
	return &Connector{policy: policy, resolver: resolver, filter: filter, client: client}, nil
}

func (connector *Connector) Query(ctx context.Context, target Target, query datasource.NormalizedQuery) (Result, error) {
	started := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	if connector == nil || connector.policy == nil || connector.resolver == nil || connector.filter == nil || connector.client == nil {
		return Result{}, queryError(ErrorInvalidQuery, errors.New("connector is not configured"))
	}
	logQL, err := buildLogQL(query)
	if err != nil {
		return Result{}, queryError(ErrorInvalidQuery, err)
	}
	endpoint, err := url.Parse(strings.TrimSpace(target.Endpoint))
	if err != nil || endpoint == nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return Result{}, queryError(ErrorPolicyRejected, outbound.ErrInvalidTarget)
	}
	base := strings.TrimRight(endpoint.String(), "/")
	fingerprint := queryFingerprint(query, logQL, base)
	cursor, err := decodeCursor(query.Cursor, fingerprint)
	if err != nil {
		return Result{}, err
	}
	if _, err := connector.policy.Validate(ctx, target.Endpoint); err != nil {
		return Result{}, queryError(ErrorPolicyRejected, err)
	}
	requestURL := base + "/loki/api/v1/query_range"
	values := url.Values{
		"query":     []string{logQL},
		"start":     []string{strconv.FormatInt(query.Start.UnixNano(), 10)},
		"end":       []string{strconv.FormatInt(query.End.UnixNano(), 10)},
		"direction": []string{query.Direction},
		"limit":     []string{strconv.Itoa(MaxQueryEntries)},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, strings.NewReader(values.Encode()))
	if err != nil {
		return Result{}, queryError(ErrorInvalidQuery, err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", "Relythra/1.0")
	queryConnector := *connector
	if target.SecretReference != nil {
		var secret secrets.Secret
		if target.ResolvedSecret != nil {
			secret = *target.ResolvedSecret
		} else {
			secret, err = connector.resolver.Resolve(ctx, *target.SecretReference)
			if err != nil {
				return Result{}, queryError(ErrorSecretUnavailable, err)
			}
		}
		request.Header.Set("Authorization", "Bearer "+secret.Reveal())
		queryConnector.filter, err = connector.filter.WithAdditionalSecrets(secret.Reveal())
		if err != nil {
			return Result{}, queryError(ErrorInvalidResponse, err)
		}
	}
	response, err := connector.client.Do(request)
	if err != nil {
		return Result{}, classifyRequestError(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if len(body) > MaxResponseBytes {
		return Result{}, queryError(ErrorResponseTooLarge, ErrResponseTooLarge)
	}
	readPartial := false
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			readPartial = true
		} else {
			return Result{}, classifyReadError(err)
		}
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return Result{}, queryError(ErrorUnauthorized, ErrUnauthorized)
	case response.StatusCode == http.StatusTooManyRequests:
		return Result{}, queryError(ErrorRateLimited, ErrRateLimited)
	case response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices:
		return Result{}, queryError(ErrorRemoteUnavailable, fmt.Errorf("HTTP status %d", response.StatusCode))
	}
	parsed, err := parseResponse(body)
	if err != nil {
		if readPartial {
			return Result{}, queryError(ErrorTimeout, err)
		}
		return Result{}, queryError(ErrorInvalidResponse, err)
	}
	if readPartial {
		addWarning(&parsed.Warnings, "Loki response stream timed out after a complete payload was received.")
	}
	responseDigest := sha256.Sum256(body)
	responseHash := hex.EncodeToString(responseDigest[:])
	if cursor != nil && cursor.ResponseDigest != responseHash {
		return Result{}, queryError(ErrorCursorExpired, ErrCursorExpired)
	}
	entries, partial, timeSkew, err := queryConnector.normalizeEntries(ctx, parsed.Data.Result, query)
	if err != nil {
		return Result{}, queryError(ErrorInvalidResponse, err)
	}
	if len(entries) >= MaxQueryEntries {
		partial = true
		addWarning(&parsed.Warnings, "Loki result reached the connector entry cap.")
	}
	if len(parsed.Warnings) != 0 {
		partial = true
	}
	if cursor != nil && cursor.Offset > len(entries) {
		return Result{}, queryError(ErrorCursorExpired, ErrCursorExpired)
	}
	offset := 0
	if cursor != nil {
		offset = cursor.Offset
	}
	end := min(offset+query.Limit, len(entries))
	page := append([]Entry(nil), entries[offset:end]...)
	nextCursor := ""
	if end < len(entries) {
		nextCursor = encodeCursor(pageCursor{Fingerprint: fingerprint, ResponseDigest: responseHash, Offset: end})
	}
	warnings, err := queryConnector.cleanWarnings(ctx, parsed.Warnings)
	if err != nil {
		return Result{}, queryError(ErrorInvalidResponse, err)
	}
	return Result{
		TemplateID: query.TemplateID, TemplateVersion: query.Version, Query: logQL,
		Start: query.Start.UTC(), End: query.End.UTC(), Direction: query.Direction, Severity: query.Severity,
		Limit: query.Limit, Duration: time.Since(started), SourceReference: requestURL,
		ResponseSHA256: responseHash, Entries: page, Warnings: warnings, NextCursor: nextCursor,
		Empty: len(entries) == 0, Partial: partial, TimeSkew: timeSkew,
	}, nil
}

type rawResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string      `json:"resultType"`
		Result     []rawStream `json:"result"`
	} `json:"data"`
	Warnings []string `json:"warnings"`
}

type rawStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

type rawLog struct {
	Timestamp string
	Line      string
	Labels    map[string]string
}

func parseResponse(body []byte) (rawResponse, error) {
	var response rawResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return rawResponse{}, errors.New("response is not valid JSON")
	}
	if response.Status != "success" || response.Data.ResultType != "streams" || response.Data.Result == nil {
		return rawResponse{}, errors.New("response does not contain Loki streams")
	}
	return response, nil
}

func (connector *Connector) normalizeEntries(ctx context.Context, streams []rawStream, query datasource.NormalizedQuery) ([]Entry, bool, bool, error) {
	entries := make([]Entry, 0)
	partial, timeSkew := false, false
	for _, stream := range streams {
		if len(stream.Stream) > MaxLogLabels {
			partial = true
			continue
		}
		redactedLabels, err := connector.filter.JSON(ctx, stream.Stream)
		if err != nil {
			return nil, partial, timeSkew, err
		}
		redactedMap, ok := redactedLabels.(map[string]any)
		if !ok {
			partial = true
			continue
		}
		labels := make(map[string]string, len(redactedMap))
		validLabels := true
		for key, rawValue := range redactedMap {
			value, isString := rawValue.(string)
			if !isString || len(key) > MaxLogLabelBytes || len(value) > MaxLogLabelBytes || strings.ContainsAny(key+value, "\x00\r\n") {
				validLabels = false
				break
			}
			labels[key] = value
		}
		if !validLabels {
			partial = true
			continue
		}
		for _, pair := range stream.Values {
			if len(entries) == MaxQueryEntries {
				partial = true
				continue
			}
			if len(pair) != 2 {
				partial = true
				continue
			}
			nanos, err := strconv.ParseInt(pair[0], 10, 64)
			if err != nil {
				partial = true
				continue
			}
			timestamp := time.Unix(0, nanos).UTC()
			outside := timestamp.Before(query.Start.Add(-maxAllowedClockSkew)) || timestamp.After(query.End.Add(maxAllowedClockSkew))
			if outside {
				timeSkew = true
			}
			line, err := connector.filter.Untrusted(ctx, "loki", pair[1], MaxLogLineBytes)
			if err != nil {
				return nil, partial, timeSkew, err
			}
			entries = append(entries, Entry{
				Timestamp: timestamp, SourceTimestamp: pair[0], Labels: labels,
				Line: line, OutsideTimeWindow: outside,
			})
		}
	}
	sort.SliceStable(entries, func(left, right int) bool {
		if entries[left].Timestamp.Equal(entries[right].Timestamp) {
			if entries[left].Line.Content == entries[right].Line.Content {
				return labelKey(entries[left].Labels) < labelKey(entries[right].Labels)
			}
			return entries[left].Line.Content < entries[right].Line.Content
		}
		if query.Direction == "forward" {
			return entries[left].Timestamp.Before(entries[right].Timestamp)
		}
		return entries[left].Timestamp.After(entries[right].Timestamp)
	})
	return entries, partial, timeSkew, nil
}

func labelKey(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(labels[key])
		builder.WriteByte('\x00')
	}
	return builder.String()
}

func buildLogQL(query datasource.NormalizedQuery) (string, error) {
	templates, issues := datasource.ResolveTemplates(datasource.SourceLoki, []string{query.TemplateID})
	if len(issues) != 0 || len(templates) != 1 || templates[0].Version != query.Version ||
		!validSlug(query.Service) || !validSlug(query.Environment) || query.Limit < 1 || query.Limit > datasource.MaxQueryLimit ||
		(query.Direction != "forward" && query.Direction != "backward") ||
		!query.End.After(query.Start) || query.End.Sub(query.Start) > datasource.MaxLokiQueryWindow {
		return "", ErrInvalidQuery
	}
	selector := "{service=" + strconv.Quote(query.Service) + ",env=" + strconv.Quote(query.Environment) + "}"
	var expression string
	switch query.TemplateID {
	case "loki.service.errors.v1":
		expression = selector + ` |~ "(?i)(error|exception|panic|failed|unavailable)"`
	case "loki.service.slow_queries.v1":
		expression = selector + ` |~ "(?i)(slow query|query_id|duration_ms)"`
	case "loki.container.restarts.v1":
		expression = selector + ` |~ "(?i)(oom|restart(ed)?|killed|exited|exit code)"`
	case "loki.service.config_errors.v1":
		expression = selector + ` |~ "(?i)(invalid config|configuration error|unknown field|config[^\n]*(invalid|error))"`
	default:
		return "", ErrInvalidQuery
	}
	if query.Severity != "" {
		severityPattern := map[string]string{
			"debug": `(?i)"level"\s*:\s*"debug"`,
			"info":  `(?i)"level"\s*:\s*"info"`,
			"warn":  `(?i)"level"\s*:\s*"(warn|warning)"`,
			"error": `(?i)"level"\s*:\s*"error"`,
		}[query.Severity]
		if severityPattern == "" {
			return "", ErrInvalidQuery
		}
		expression += ` |~ ` + strconv.Quote(severityPattern)
	}
	return expression, nil
}

func validSlug(value string) bool {
	if value == "" || len(value) > 63 ||
		!(value[0] >= 'a' && value[0] <= 'z' || value[0] >= '0' && value[0] <= '9') {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func queryFingerprint(query datasource.NormalizedQuery, logQL, endpoint string) string {
	canonical := strings.Join([]string{
		query.TemplateID, strconv.Itoa(query.Version), query.Service, query.Environment,
		query.Direction, query.Severity, query.Start.UTC().Format(time.RFC3339Nano),
		query.End.UTC().Format(time.RFC3339Nano), strconv.Itoa(query.Limit), logQL, endpoint,
	}, "\x00")
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}

type pageCursor struct {
	Fingerprint    string `json:"q"`
	ResponseDigest string `json:"r"`
	Offset         int    `json:"o"`
}

func encodeCursor(cursor pageCursor) string {
	encoded, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func decodeCursor(raw, fingerprint string) (*pageCursor, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > maxCursorBytes {
		return nil, queryError(ErrorInvalidCursor, ErrInvalidCursor)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, queryError(ErrorInvalidCursor, ErrInvalidCursor)
	}
	var cursor pageCursor
	if json.Unmarshal(decoded, &cursor) != nil || cursor.Offset < 1 || cursor.Offset > MaxQueryEntries ||
		len(cursor.ResponseDigest) != sha256.Size*2 || cursor.Fingerprint != fingerprint {
		return nil, queryError(ErrorInvalidCursor, ErrInvalidCursor)
	}
	if _, err := hex.DecodeString(cursor.ResponseDigest); err != nil {
		return nil, queryError(ErrorInvalidCursor, ErrInvalidCursor)
	}
	return &cursor, nil
}

func (connector *Connector) cleanWarnings(ctx context.Context, warnings []string) ([]string, error) {
	cleaned := make([]string, 0, min(len(warnings), MaxWarnings))
	for _, warning := range warnings {
		if len(cleaned) == MaxWarnings {
			break
		}
		clean, err := connector.filter.Text(ctx, warning)
		if err != nil {
			return nil, err
		}
		clean = strings.Map(func(character rune) rune {
			if character < 0x20 || character == 0x7f {
				return ' '
			}
			return character
		}, strings.TrimSpace(clean))
		if len(clean) > MaxWarningLength {
			clean = clean[:MaxWarningLength]
		}
		if clean != "" {
			cleaned = append(cleaned, clean)
		}
	}
	return cleaned, nil
}

func addWarning(warnings *[]string, warning string) {
	if len(*warnings) < MaxWarnings {
		*warnings = append(*warnings, warning)
	}
}

func classifyRequestError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return queryError(ErrorTimeout, err)
	}
	if errors.Is(err, outbound.ErrRedirectBlocked) || errors.Is(err, outbound.ErrUnsafeAddress) ||
		errors.Is(err, outbound.ErrHostNotAllowed) || errors.Is(err, outbound.ErrPortNotAllowed) ||
		errors.Is(err, outbound.ErrSchemeNotAllowed) || errors.Is(err, outbound.ErrResolutionFailed) {
		return queryError(ErrorPolicyRejected, err)
	}
	return queryError(ErrorNetwork, err)
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
