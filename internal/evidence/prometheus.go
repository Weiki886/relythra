package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/security/redact"
)

// PrometheusEvidenceContext supplies investigation ownership omitted by the connector result.
type PrometheusEvidenceContext struct {
	InvestigationID string
	ToolCallID      string
	EntityType      string
	EntityID        string
	CollectedAt     time.Time
}

type prometheusQueryParameters struct {
	TemplateID      string `json:"template_id"`
	TemplateVersion int    `json:"template_version"`
	QueryType       string `json:"query_type"`
	Unit            string `json:"unit"`
	Step            string `json:"step"`
	ResponseSHA256  string `json:"response_sha256"`
}

type prometheusValueSummary struct {
	Series   []prometheusconnector.Series `json:"series"`
	Warnings []string                     `json:"warnings"`
}

// FromPrometheusResult turns one bounded connector query into a canonical Evidence record.
func FromPrometheusResult(
	ctx context.Context,
	result prometheusconnector.Result,
	metadata PrometheusEvidenceContext,
	filter *redact.Filter,
) (Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if result.TemplateID == "" || result.TemplateVersion <= 0 || result.QueryType == "" || result.Query == "" {
		return Record{}, ErrInvalidInput
	}
	queryParameters, err := json.Marshal(prometheusQueryParameters{
		TemplateID: result.TemplateID, TemplateVersion: result.TemplateVersion,
		QueryType: result.QueryType, Unit: result.Unit, Step: result.Step.String(),
		ResponseSHA256: result.ResponseSHA256,
	})
	if err != nil {
		return Record{}, fmt.Errorf("%w: encode Prometheus query metadata", ErrInvalidInput)
	}
	series := result.Series
	if series == nil {
		series = []prometheusconnector.Series{}
	}
	warnings := result.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	valueSummary, err := json.Marshal(prometheusValueSummary{Series: series, Warnings: warnings})
	if err != nil {
		return Record{}, fmt.Errorf("%w: encode Prometheus result", ErrInvalidInput)
	}
	completeness := CompletenessComplete
	switch {
	case result.Empty:
		completeness = CompletenessMissing
	case result.Stale:
		completeness = CompletenessExpired
	case result.Partial || len(result.Warnings) > 0:
		completeness = CompletenessPartial
	}
	var freshnessSeconds *int
	if result.LatestSampleAt != nil && !result.LatestSampleAt.After(metadata.CollectedAt) {
		age := int(metadata.CollectedAt.Sub(*result.LatestSampleAt) / time.Second)
		freshnessSeconds = &age
	}
	input := Input{
		InvestigationID:   metadata.InvestigationID,
		ToolCallID:        metadata.ToolCallID,
		SourceType:        SourcePrometheus,
		EntityType:        metadata.EntityType,
		EntityID:          metadata.EntityID,
		ObservedStart:     result.Start,
		ObservedEnd:       result.End,
		CollectedAt:       metadata.CollectedAt,
		QueryText:         result.Query,
		RawReference:      result.SourceReference,
		QueryParameters:   queryParameters,
		ValueSummary:      valueSummary,
		Completeness:      completeness,
		FreshnessSeconds:  freshnessSeconds,
		IndependenceGroup: fmt.Sprintf("prometheus:%s:v%d", result.TemplateID, result.TemplateVersion),
		SourceTimezone:    "UTC",
		SourceTimeText:    result.Start.UTC().Format(time.RFC3339Nano) + "/" + result.End.UTC().Format(time.RFC3339Nano),
	}
	return Normalize(ctx, input, filter)
}
