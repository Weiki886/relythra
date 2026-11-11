package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/security/redact"
)

func validCollectionGap() CollectionGapInput {
	start := time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC)
	return CollectionGapInput{
		InvestigationID: investigationID,
		ToolCallID:      "55555555-5555-4555-8555-555555555555",
		SourceType:      SourcePrometheus,
		EntityType:      "SERVICE",
		EntityID:        "checkout-api",
		TemplateID:      "prometheus.service.latency.v1",
		TemplateVersion: 1,
		ObservedStart:   start,
		ObservedEnd:     start.Add(5 * time.Minute),
		CollectedAt:     start.Add(6 * time.Minute),
		ReasonCode:      CollectionFailureTimeout,
	}
}

func TestFromCollectionFailureCreatesStructuredMissingEvidence(t *testing.T) {
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	input := validCollectionGap()
	record, err := FromCollectionFailure(context.Background(), input, filter)
	if err != nil {
		t.Fatal(err)
	}
	if record.SourceType != SourcePrometheus || record.Completeness != CompletenessMissing ||
		record.RawReference != "" || record.QueryText != "" || record.EntityID == nil || *record.EntityID != input.EntityID ||
		record.IndependenceGroup != "prometheus:prometheus.service.latency.v1:v1" {
		t.Fatalf("collection gap record = %+v", record)
	}
	var summary map[string]any
	if err := json.Unmarshal(record.ValueSummary, &summary); err != nil {
		t.Fatal(err)
	}
	if summary["kind"] != "collection_gap" || summary["reason_code"] != string(CollectionFailureTimeout) ||
		summary["template_id"] != input.TemplateID || summary["template_version"] != float64(input.TemplateVersion) {
		t.Fatalf("collection gap summary = %#v", summary)
	}
	if err := Validate(record); err != nil {
		t.Fatalf("normalized record is invalid: %v", err)
	}
}

func TestFromCollectionFailureAcceptsRegisteredTemplatesBySource(t *testing.T) {
	filter, _ := redact.NewFilter()
	for _, testCase := range []struct {
		source     string
		templateID string
	}{
		{source: SourcePrometheus, templateID: "prometheus.service.latency.v1"},
		{source: SourceLoki, templateID: "loki.service.errors.v1"},
		{source: SourceGitHub, templateID: "github.commits.v1"},
		{source: SourceRuntime, templateID: "runtime.containers.v1"},
	} {
		t.Run(testCase.source, func(t *testing.T) {
			input := validCollectionGap()
			input.SourceType = testCase.source
			input.TemplateID = testCase.templateID
			if _, err := FromCollectionFailure(context.Background(), input, filter); err != nil {
				t.Fatalf("FromCollectionFailure(%s, %s): %v", testCase.source, testCase.templateID, err)
			}
		})
	}
}

func TestFromCollectionFailureHashIsStableAcrossReplay(t *testing.T) {
	filter, _ := redact.NewFilter()
	input := validCollectionGap()
	first, err := FromCollectionFailure(context.Background(), input, filter)
	if err != nil {
		t.Fatal(err)
	}
	input.ToolCallID = "66666666-6666-4666-8666-666666666666"
	input.CollectedAt = input.CollectedAt.Add(time.Minute)
	second, err := FromCollectionFailure(context.Background(), input, filter)
	if err != nil {
		t.Fatal(err)
	}
	if first.ContentHash != second.ContentHash {
		t.Fatalf("replay hashes differ: %s != %s", first.ContentHash, second.ContentHash)
	}
}

func TestFromCollectionFailureRejectsInvalidScopeAndFreeFormErrors(t *testing.T) {
	filter, _ := redact.NewFilter()
	for _, testCase := range []struct {
		name   string
		mutate func(*CollectionGapInput)
	}{
		{name: "unknown source", mutate: func(input *CollectionGapInput) { input.SourceType = "UNKNOWN" }},
		{name: "template source mismatch", mutate: func(input *CollectionGapInput) { input.TemplateID = "loki.service.logs.v1" }},
		{name: "unknown reason", mutate: func(input *CollectionGapInput) { input.ReasonCode = "connection refused: token=secret" }},
		{name: "invalid template version", mutate: func(input *CollectionGapInput) { input.TemplateVersion = 0 }},
		{name: "invalid time range", mutate: func(input *CollectionGapInput) { input.ObservedEnd = input.ObservedStart.Add(-time.Second) }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			input := validCollectionGap()
			testCase.mutate(&input)
			if _, err := FromCollectionFailure(context.Background(), input, filter); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestFromCollectionFailureRejectsMissingRedactionFilter(t *testing.T) {
	if _, err := FromCollectionFailure(context.Background(), validCollectionGap(), nil); !errors.Is(err, redact.ErrUnsafeOutput) {
		t.Fatalf("error = %v, want ErrUnsafeOutput", err)
	}
}
