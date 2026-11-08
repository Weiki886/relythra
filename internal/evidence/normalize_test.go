package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/security/redact"
)

const investigationID = "44444444-4444-4444-8444-444444444444"

func TestNormalizeCanonicalizesTimesAndHashesRedactedObservation(t *testing.T) {
	filter, err := redact.NewFilter("known-redaction-value")
	if err != nil {
		t.Fatal(err)
	}
	input := validInput()
	input.ObservedStart = time.Date(2026, 11, 8, 10, 0, 0, 0, time.FixedZone("source", 8*60*60))
	input.ObservedEnd = input.ObservedStart.Add(5 * time.Minute)
	input.CollectedAt = input.CollectedAt.In(time.FixedZone("collector", -5*60*60))
	input.SourceTimezone = "+08:00"
	input.SourceTimeText = "2026-11-08T18:00:00+08:00"
	input.QueryText = "sum(rate(http_requests_total{token=\"known-redaction-value\"}[5m]))"
	input.QueryParameters = json.RawMessage(`{"window":"5m","token":"known-redaction-value"}`)
	input.ValueSummary = json.RawMessage(`{"p95_ms":420,"password":"known-redaction-value"}`)
	input.RawReference = "https://prometheus.example.test/graph?token=known-redaction-value"

	first, err := Normalize(context.Background(), input, filter)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if first.ObservedStart.Location() != time.UTC || first.ObservedEnd.Location() != time.UTC || first.CollectedAt.Location() != time.UTC {
		t.Fatal("normalized timestamps are not UTC")
	}
	if first.SourceTimezone != "+08:00" || first.SourceTimeText != input.SourceTimeText {
		t.Fatalf("source time metadata changed: %q / %q", first.SourceTimezone, first.SourceTimeText)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "known-redaction-value") {
		t.Fatalf("normalized record exposed secret: %s", encoded)
	}

	replay := input
	replay.CollectedAt = replay.CollectedAt.Add(24 * time.Hour)
	replay.ToolCallID = "55555555-5555-4555-8555-555555555555"
	second, err := Normalize(context.Background(), replay, filter)
	if err != nil {
		t.Fatalf("normalize replay: %v", err)
	}
	if first.ContentHash != second.ContentHash {
		t.Fatalf("replay hash changed: %s != %s", first.ContentHash, second.ContentHash)
	}
}

func TestNormalizeRejectsInvalidContractAndFailsClosed(t *testing.T) {
	filter, _ := redact.NewFilter()
	for _, testCase := range []struct {
		name   string
		mutate func(*Input)
	}{
		{name: "missing investigation", mutate: func(input *Input) { input.InvestigationID = "" }},
		{name: "unknown source", mutate: func(input *Input) { input.SourceType = "UNKNOWN" }},
		{name: "inverted interval", mutate: func(input *Input) { input.ObservedEnd = input.ObservedStart.Add(-time.Second) }},
		{name: "missing collection time", mutate: func(input *Input) { input.CollectedAt = time.Time{} }},
		{name: "unsupported completeness", mutate: func(input *Input) { input.Completeness = "SOMEDAY" }},
		{name: "invalid summary", mutate: func(input *Input) { input.ValueSummary = json.RawMessage(`[]`) }},
		{name: "invalid query snapshot", mutate: func(input *Input) { input.QueryParameters = json.RawMessage(`[]`) }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			input := validInput()
			testCase.mutate(&input)
			if _, err := Normalize(context.Background(), input, filter); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}

	unsafeFilter, _ := redact.NewFilter("secret-from-output")
	input := validInput()
	input.ValueSummary = json.RawMessage(`{"message":"secret-from-output"}`)
	if _, err := Normalize(context.Background(), input, unsafeFilter); err != nil {
		t.Fatalf("known secrets should be redacted: %v", err)
	}
	if _, err := Normalize(context.Background(), validInput(), nil); !errors.Is(err, redact.ErrUnsafeOutput) {
		t.Fatalf("nil redactor error = %v, want fail-closed redaction error", err)
	}
}

func TestValidateRejectsMutatedNormalizedRecord(t *testing.T) {
	filter, _ := redact.NewFilter()
	input := validInput()
	record, err := Normalize(context.Background(), input, filter)
	if err != nil {
		t.Fatal(err)
	}
	record.QueryParameters = json.RawMessage(`[]`)
	if err := Validate(record); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("mutated record validation error = %v, want ErrInvalidInput", err)
	}
}

func TestNormalizeAllowsMissingEvidenceWithoutQueryOrReference(t *testing.T) {
	filter, _ := redact.NewFilter()
	input := validInput()
	input.QueryText = ""
	input.RawReference = ""
	input.Completeness = CompletenessMissing
	record, err := Normalize(context.Background(), input, filter)
	if err != nil {
		t.Fatalf("normalize missing evidence: %v", err)
	}
	if record.QueryText != "" || record.RawReference != "" || record.Completeness != CompletenessMissing {
		t.Fatalf("missing evidence normalized unexpectedly: %+v", record)
	}
}

func TestNormalizeRejectsTextThatExceedsLimitAfterRedaction(t *testing.T) {
	filter, _ := redact.NewFilter("x")
	input := validInput()
	input.QueryText = strings.Repeat("x", maxTextBytes)
	if _, err := Normalize(context.Background(), input, filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized redacted query error = %v, want ErrInvalidInput", err)
	}
}

func validInput() Input {
	return Input{
		InvestigationID:   investigationID,
		SourceType:        SourcePrometheus,
		EntityType:        "service",
		EntityID:          "service-123",
		ObservedStart:     time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC),
		ObservedEnd:       time.Date(2026, 11, 8, 10, 5, 0, 0, time.UTC),
		CollectedAt:       time.Date(2026, 11, 8, 10, 5, 2, 0, time.UTC),
		QueryText:         "sum(rate(http_requests_total[5m]))",
		RawReference:      "https://prometheus.example.test/graph",
		QueryParameters:   json.RawMessage(`{"window":"5m"}`),
		ValueSummary:      json.RawMessage(`{"p95_ms":420}`),
		Completeness:      CompletenessComplete,
		IndependenceGroup: "prometheus:latency",
	}
}
