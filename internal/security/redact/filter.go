// Package redact applies a single fail-closed boundary to text and structured
// data that may leave the process through logs, APIs, audit, evidence, or LLM
// prompts.
package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// RedactedValue is the stable replacement used by all outbound boundaries.
	RedactedValue        = "[REDACTED]"
	untrustedTrust       = "untrusted_data"
	DefaultUntrustedSize = 64 * 1024
	MaxUntrustedSize     = 1024 * 1024
)

var (
	ErrUnsafeOutput  = errors.New("redaction could not produce safe output")
	ErrInvalidLimit  = errors.New("untrusted data limit is invalid")
	ErrInvalidSource = errors.New("untrusted data source is invalid")

	untrustedSource = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

type replacementRule struct {
	expression  *regexp.Regexp
	replacement string
}

var textRules = []replacementRule{
	{
		expression: regexp.MustCompile(
			`(?s)(-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----).*?(-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----)`,
		),
		replacement: `$1` + RedactedValue + `$2`,
	},
	{
		expression:  regexp.MustCompile(`(?im)(authorization[ \t]*:[ \t]*)[^\r\n]+`),
		replacement: `$1` + RedactedValue,
	},
	{
		expression: regexp.MustCompile(
			`(?im)((?:x-api-key|api-key|x-auth-token|proxy-authorization|cookie|set-cookie)[ \t]*:[ \t]*)[^\r\n]+`,
		),
		replacement: `$1` + RedactedValue,
	},
	{
		expression:  regexp.MustCompile(`(?i)\b(Bearer|Basic|Token)([ \t]+)[A-Za-z0-9._~+/=-]+`),
		replacement: `$1$2` + RedactedValue,
	},
	{
		expression:  regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)([^/@\s]+)@`),
		replacement: `$1` + RedactedValue + `@`,
	},
	{
		expression: regexp.MustCompile(
			`(?i)([?&](?:access[_-]?token|auth[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|apikey|password|passwd|secret|signature|sig|auth|authorization|key)=)([^&#\s]*)`,
		),
		replacement: `$1` + RedactedValue,
	},
	{
		expression: regexp.MustCompile(
			`(?i)\b(token|secret|password|passwd|api[_-]?key|authorization)([ \t]*[:=][ \t]*)([^\s,;]+)`,
		),
		replacement: `$1$2` + RedactedValue,
	},
	{
		expression:  regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
		replacement: `[REDACTED JWT]`,
	},
	{
		expression: regexp.MustCompile(
			`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`,
		),
		replacement: `[REDACTED GITHUB TOKEN]`,
	},
	{
		expression:  regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
		replacement: `[REDACTED SLACK TOKEN]`,
	},
	{
		expression:  regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
		replacement: `[REDACTED AWS KEY]`,
	},
	{
		expression:  regexp.MustCompile(`\bsk-(?:proj-|live-)?[A-Za-z0-9_-]{16,}\b`),
		replacement: `[REDACTED API KEY]`,
	},
}

// Filter combines registered runtime secrets with fixed credential patterns.
// A Filter is immutable after construction and safe for concurrent use.
type Filter struct {
	knownSecrets []string

	// forceFailure is set only by package tests to prove callers fail closed.
	forceFailure bool
}

func NewFilter(knownSecrets ...string) (*Filter, error) {
	unique := make(map[string]struct{}, len(knownSecrets))
	for _, secret := range knownSecrets {
		if secret == "" || secret == RedactedValue {
			continue
		}
		unique[secret] = struct{}{}
	}

	secrets := make([]string, 0, len(unique))
	for secret := range unique {
		secrets = append(secrets, secret)
	}
	sort.Slice(secrets, func(i, j int) bool {
		return len(secrets[i]) > len(secrets[j])
	})
	return &Filter{knownSecrets: secrets}, nil
}

// WithAdditionalSecrets returns an immutable filter that also knows credentials
// scoped to one outbound query. The original filter remains unchanged.
func (filter *Filter) WithAdditionalSecrets(knownSecrets ...string) (*Filter, error) {
	if filter == nil || filter.forceFailure {
		return nil, ErrUnsafeOutput
	}
	combined := make([]string, 0, len(filter.knownSecrets)+len(knownSecrets))
	combined = append(combined, filter.knownSecrets...)
	combined = append(combined, knownSecrets...)
	return NewFilter(combined...)
}

// Text redacts known secrets and credential-shaped substrings. It returns an
// error with no output when any registered secret remains.
func (filter *Filter) Text(ctx context.Context, input string) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	if filter == nil || filter.forceFailure {
		return "", ErrUnsafeOutput
	}

	output := input
	for _, secret := range filter.knownSecrets {
		output = strings.ReplaceAll(output, secret, RedactedValue)
	}
	for _, rule := range textRules {
		output = rule.expression.ReplaceAllString(output, rule.replacement)
	}

	for _, secret := range filter.knownSecrets {
		if strings.Contains(output, secret) {
			return "", ErrUnsafeOutput
		}
	}
	for _, rule := range textRules {
		if rule.expression.MatchString(output) {
			// Matching field names without values can be safe, so only enforce
			// this invariant for patterns that cannot be diagnostic labels.
			if rule.replacement == `[REDACTED JWT]` ||
				rule.replacement == `[REDACTED GITHUB TOKEN]` ||
				rule.replacement == `[REDACTED SLACK TOKEN]` ||
				rule.replacement == `[REDACTED AWS KEY]` ||
				rule.replacement == `[REDACTED API KEY]` {
				return "", ErrUnsafeOutput
			}
		}
	}
	return output, nil
}

// JSON normalizes a value to JSON data and redacts sensitive fields
// recursively while preserving their names.
func (filter *Filter) JSON(ctx context.Context, value any) (any, error) {
	if filter == nil {
		return nil, ErrUnsafeOutput
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: value is not JSON serializable", ErrUnsafeOutput)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, fmt.Errorf("%w: value is not valid JSON", ErrUnsafeOutput)
	}
	return filter.redactJSONValue(ctx, normalized)
}

func (filter *Filter) redactJSONValue(ctx context.Context, value any) (any, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	switch typed := value.(type) {
	case map[string]any:
		output := make(map[string]any, len(typed))
		for key, child := range typed {
			safeKey, err := filter.Text(ctx, key)
			if err != nil {
				return nil, err
			}
			if _, exists := output[safeKey]; exists {
				return nil, fmt.Errorf("%w: redacted JSON keys collide", ErrUnsafeOutput)
			}
			if IsSensitiveKey(key) || IsSensitiveKey(safeKey) {
				output[safeKey] = RedactedValue
				continue
			}
			redacted, err := filter.redactJSONValue(ctx, child)
			if err != nil {
				return nil, err
			}
			output[safeKey] = redacted
		}
		return output, nil
	case []any:
		output := make([]any, len(typed))
		for index, child := range typed {
			redacted, err := filter.redactJSONValue(ctx, child)
			if err != nil {
				return nil, err
			}
			output[index] = redacted
		}
		return output, nil
	case string:
		return filter.Text(ctx, typed)
	case nil, bool, json.Number:
		return typed, nil
	default:
		return nil, ErrUnsafeOutput
	}
}

// UntrustedData is the only representation used for external text in a model
// context. Its explicit trust marker separates data from system instructions.
type UntrustedData struct {
	Trust         string `json:"trust"`
	Source        string `json:"source"`
	Content       string `json:"content"`
	OriginalBytes int    `json:"original_bytes"`
	Truncated     bool   `json:"truncated"`
}

func (filter *Filter) Untrusted(
	ctx context.Context,
	source string,
	content string,
	limit int,
) (UntrustedData, error) {
	if filter == nil {
		return UntrustedData{}, ErrUnsafeOutput
	}
	if !untrustedSource.MatchString(source) || !utf8.ValidString(source) {
		return UntrustedData{}, ErrInvalidSource
	}
	safeSource, err := filter.Text(ctx, source)
	if err != nil || safeSource != source {
		return UntrustedData{}, ErrInvalidSource
	}
	if limit <= 0 || limit > MaxUntrustedSize {
		return UntrustedData{}, ErrInvalidLimit
	}
	redacted, err := filter.Text(ctx, content)
	if err != nil {
		return UntrustedData{}, err
	}
	truncated, wasTruncated := truncateUTF8(redacted, limit)
	return UntrustedData{
		Trust:         untrustedTrust,
		Source:        source,
		Content:       truncated,
		OriginalBytes: len(content),
		Truncated:     wasTruncated,
	}, nil
}

// IsSensitiveKey reports whether a structured field name conventionally carries
// credential material.
func IsSensitiveKey(key string) bool {
	normalized := normalizeKey(key)
	switch normalized {
	case "authorization",
		"proxyauthorization",
		"cookie",
		"setcookie",
		"password",
		"passwd",
		"secret",
		"clientsecret",
		"token",
		"accesstoken",
		"refreshtoken",
		"idtoken",
		"authtoken",
		"apikey",
		"privatekey",
		"credential",
		"credentials",
		"signature":
		return true
	}
	return strings.HasSuffix(normalized, "password") ||
		strings.HasSuffix(normalized, "secret") ||
		strings.HasSuffix(normalized, "token") ||
		strings.HasSuffix(normalized, "credential")
}

func normalizeKey(key string) string {
	return strings.Map(func(value rune) rune {
		if unicode.IsLetter(value) || unicode.IsDigit(value) {
			return unicode.ToLower(value)
		}
		return -1
	}, key)
}

func truncateUTF8(value string, limit int) (string, bool) {
	if len(value) <= limit {
		return value, false
	}
	end := limit
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end], true
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeOutput, err)
	}
	return nil
}
