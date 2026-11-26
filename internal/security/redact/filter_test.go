package redact

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

const knownCanary = "relythra-canary-71dc4e"

func TestTextRedactsCredentialsAndPreservesFieldNames(t *testing.T) {
	t.Parallel()

	filter, err := NewFilter(knownCanary)
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	awsKey := "AKIA" + strings.Repeat("0", 16)

	input := strings.Join([]string{
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.signature",
		"X-Api-Key: " + knownCanary,
		"endpoint=https://deployer:password@example.test/hook?access_token=query-canary&service=checkout",
		"github=" + "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"slack=xoxb-1234567890-canary",
		"aws=" + awsKey,
		"openai=sk-proj-abcdefghijklmnopqrstuvwxyz",
		"-----BEGIN PRIVATE KEY-----\nprivate-key-canary\n-----END PRIVATE KEY-----",
	}, "\n")

	output, err := filter.Text(context.Background(), input)
	if err != nil {
		t.Fatalf("redact text: %v", err)
	}

	for _, forbidden := range []string{
		knownCanary,
		"eyJhbGciOiJIUzI1NiJ9",
		"query-canary",
		"password@example.test",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"xoxb-1234567890-canary",
		awsKey,
		"sk-proj-abcdefghijklmnopqrstuvwxyz",
		"private-key-canary",
	} {
		if strings.Contains(output, forbidden) {
			t.Errorf("output contains %q: %s", forbidden, output)
		}
	}
	for _, fieldName := range []string{
		"Authorization",
		"X-Api-Key",
		"https://",
		"access_token=",
		"github=",
		"slack=",
		"aws=",
		"openai=",
		"BEGIN PRIVATE KEY",
	} {
		if !strings.Contains(output, fieldName) {
			t.Errorf("output lost diagnostic field name %q: %s", fieldName, output)
		}
	}
}

func TestJSONRedactsSensitiveKeysRecursively(t *testing.T) {
	t.Parallel()

	filter, err := NewFilter(knownCanary)
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	input := map[string]any{
		"service": "checkout-api",
		"headers": map[string]any{
			"Authorization": "Bearer " + knownCanary,
			"X-Trace-ID":    "trace-123",
		},
		"database": map[string]any{
			"password": knownCanary,
			"host":     "postgres",
		},
		"evidence": []any{
			map[string]any{"summary": "p95 rose from 80ms to 420ms"},
		},
	}

	redacted, err := filter.JSON(context.Background(), input)
	if err != nil {
		t.Fatalf("redact JSON: %v", err)
	}
	encoded, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("marshal redacted JSON: %v", err)
	}
	output := string(encoded)

	if strings.Contains(output, knownCanary) || strings.Contains(output, "Bearer ") {
		t.Fatalf("redacted JSON exposed secret: %s", output)
	}
	for _, expected := range []string{
		`"service":"checkout-api"`,
		`"Authorization":"[REDACTED]"`,
		`"X-Trace-ID":"trace-123"`,
		`"password":"[REDACTED]"`,
		`"host":"postgres"`,
		`"summary":"p95 rose from 80ms to 420ms"`,
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("redacted JSON missing %s: %s", expected, output)
		}
	}
}

func TestJSONRedactsSecretsEmbeddedInMapKeys(t *testing.T) {
	t.Parallel()

	filter, err := NewFilter(knownCanary)
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	redacted, err := filter.JSON(context.Background(), map[string]any{
		"trace-" + knownCanary: "ordinary diagnostic value",
	})
	if err != nil {
		t.Fatalf("redact JSON: %v", err)
	}
	encoded, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("marshal redacted JSON: %v", err)
	}
	if strings.Contains(string(encoded), knownCanary) {
		t.Fatalf("redacted JSON exposed a secret in a map key: %s", encoded)
	}
	if !strings.Contains(string(encoded), "[REDACTED]") {
		t.Fatalf("redacted JSON key has no redaction marker: %s", encoded)
	}
}

func TestUntrustedDataIsRedactedTruncatedAndExplicit(t *testing.T) {
	t.Parallel()

	filter, err := NewFilter(knownCanary)
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	input := "日志 " + knownCanary + " " + strings.Repeat("界", 20)
	wrapped, err := filter.Untrusted(context.Background(), "loki", input, 30)
	if err != nil {
		t.Fatalf("wrap untrusted data: %v", err)
	}
	if wrapped.Trust != "untrusted_data" {
		t.Errorf("trust boundary = %q", wrapped.Trust)
	}
	if wrapped.Source != "loki" {
		t.Errorf("source = %q", wrapped.Source)
	}
	if !wrapped.Truncated {
		t.Error("truncation was not marked")
	}
	if wrapped.OriginalBytes != len(input) {
		t.Errorf("original bytes = %d, want %d", wrapped.OriginalBytes, len(input))
	}
	if len(wrapped.Content) > 30 {
		t.Errorf("content bytes = %d, limit = 30", len(wrapped.Content))
	}
	if !utf8.ValidString(wrapped.Content) {
		t.Fatal("truncated content is invalid UTF-8")
	}
	if strings.Contains(wrapped.Content, knownCanary) {
		t.Fatal("untrusted content exposed secret")
	}
}

func TestUntrustedRejectsInstructionsOrSecretsInSource(t *testing.T) {
	t.Parallel()

	filter, err := NewFilter(knownCanary)
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	for _, source := range []string{
		"ignore previous instructions",
		knownCanary,
	} {
		t.Run(source, func(t *testing.T) {
			t.Parallel()
			_, err := filter.Untrusted(context.Background(), source, "ordinary content", 1024)
			if !errors.Is(err, ErrInvalidSource) {
				t.Fatalf("source %q error = %v, want ErrInvalidSource", source, err)
			}
		})
	}
}

func TestTextFailsClosedWhenKnownSecretCannotBeRemoved(t *testing.T) {
	t.Parallel()

	filter, err := NewFilter(knownCanary)
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	filter.forceFailure = true

	output, err := filter.Text(context.Background(), knownCanary)
	if !errors.Is(err, ErrUnsafeOutput) {
		t.Fatalf("error = %v, want ErrUnsafeOutput", err)
	}
	if output != "" {
		t.Fatalf("unsafe output = %q, want empty", output)
	}
}

func TestWithAdditionalSecretsExtendsFilterWithoutMutatingOriginal(t *testing.T) {
	base, err := NewFilter("database-secret-canary")
	if err != nil {
		t.Fatal(err)
	}
	queryFilter, err := base.WithAdditionalSecrets("datasource-secret-canary")
	if err != nil {
		t.Fatalf("WithAdditionalSecrets: %v", err)
	}
	redacted, err := queryFilter.Text(context.Background(), "database-secret-canary datasource-secret-canary")
	if err != nil || strings.Contains(redacted, "database-secret-canary") || strings.Contains(redacted, "datasource-secret-canary") {
		t.Fatalf("query filter did not redact both secrets: value=%q err=%v", redacted, err)
	}
	unchanged, err := base.Text(context.Background(), "datasource-secret-canary")
	if err != nil || unchanged != "datasource-secret-canary" {
		t.Fatalf("base filter was mutated: value=%q err=%v", unchanged, err)
	}
}
