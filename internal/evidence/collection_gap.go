package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/security/redact"
)

type CollectionFailureCode string

const (
	CollectionFailureTimeout          CollectionFailureCode = "timeout"
	CollectionFailureRateLimited      CollectionFailureCode = "rate_limited"
	CollectionFailurePermissionDenied CollectionFailureCode = "permission_denied"
	CollectionFailureUnavailable      CollectionFailureCode = "unavailable"
	CollectionFailureInvalidResponse  CollectionFailureCode = "invalid_response"
	CollectionFailureRequestRejected  CollectionFailureCode = "request_rejected"
	CollectionFailureUnknown          CollectionFailureCode = "unknown"
)

type CollectionGapInput struct {
	InvestigationID string
	ToolCallID      string
	SourceType      string
	EntityType      string
	EntityID        string
	TemplateID      string
	TemplateVersion int
	ObservedStart   time.Time
	ObservedEnd     time.Time
	CollectedAt     time.Time
	ReasonCode      CollectionFailureCode
}

type collectionGapQueryParameters struct {
	TemplateID      string `json:"template_id"`
	TemplateVersion int    `json:"template_version"`
}

type collectionGapSummary struct {
	Kind            string                `json:"kind"`
	ReasonCode      CollectionFailureCode `json:"reason_code"`
	TemplateID      string                `json:"template_id"`
	TemplateVersion int                   `json:"template_version"`
}

// FromCollectionFailure records a safe, structured gap for one failed source
// query. It deliberately accepts a reason code instead of an error string.
func FromCollectionFailure(
	ctx context.Context,
	input CollectionGapInput,
	filter *redact.Filter,
) (Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if filter == nil {
		return Record{}, redact.ErrUnsafeOutput
	}
	if !domain.IsID(input.InvestigationID) ||
		(input.ToolCallID != "" && !domain.IsID(input.ToolCallID)) ||
		!validCollectionSource(input.SourceType) ||
		!validCollectionTemplate(input.SourceType, input.TemplateID) ||
		input.TemplateVersion <= 0 || !validCollectionFailureCode(input.ReasonCode) ||
		domain.ValidateTimeRange(input.ObservedStart, input.ObservedEnd) != nil || input.CollectedAt.IsZero() ||
		strings.TrimSpace(input.EntityType) == "" || input.EntityType != strings.TrimSpace(input.EntityType) {
		return Record{}, ErrInvalidInput
	}
	queryParameters, err := json.Marshal(collectionGapQueryParameters{
		TemplateID: input.TemplateID, TemplateVersion: input.TemplateVersion,
	})
	if err != nil {
		return Record{}, fmt.Errorf("%w: encode collection gap parameters", ErrInvalidInput)
	}
	valueSummary, err := json.Marshal(collectionGapSummary{
		Kind: "collection_gap", ReasonCode: input.ReasonCode,
		TemplateID: input.TemplateID, TemplateVersion: input.TemplateVersion,
	})
	if err != nil {
		return Record{}, fmt.Errorf("%w: encode collection gap summary", ErrInvalidInput)
	}
	return Normalize(ctx, Input{
		InvestigationID: input.InvestigationID, ToolCallID: input.ToolCallID,
		SourceType: input.SourceType, EntityType: input.EntityType, EntityID: input.EntityID,
		ObservedStart: input.ObservedStart, ObservedEnd: input.ObservedEnd, CollectedAt: input.CollectedAt,
		QueryParameters: queryParameters, ValueSummary: valueSummary,
		Completeness:      CompletenessMissing,
		IndependenceGroup: fmt.Sprintf("%s:%s:v%d", strings.ToLower(input.SourceType), input.TemplateID, input.TemplateVersion),
		SourceTimezone:    "UTC",
		SourceTimeText:    input.ObservedStart.UTC().Format(time.RFC3339Nano) + "/" + input.ObservedEnd.UTC().Format(time.RFC3339Nano),
	}, filter)
}

func validCollectionSource(source string) bool {
	switch source {
	case SourcePrometheus, SourceLoki, SourceGitHub, SourceRuntime:
		return true
	default:
		return false
	}
}

func validCollectionTemplate(source, templateID string) bool {
	registeredSource := map[string]datasource.SourceType{
		SourcePrometheus: datasource.SourcePrometheus,
		SourceLoki:       datasource.SourceLoki,
		SourceGitHub:     datasource.SourceGitHub,
		SourceRuntime:    datasource.SourceRuntime,
	}[source]
	if registeredSource == "" {
		return false
	}
	_, issues := datasource.ResolveTemplates(registeredSource, []string{templateID})
	return len(issues) == 0
}

func validCollectionFailureCode(code CollectionFailureCode) bool {
	switch code {
	case CollectionFailureTimeout, CollectionFailureRateLimited, CollectionFailurePermissionDenied,
		CollectionFailureUnavailable, CollectionFailureInvalidResponse, CollectionFailureRequestRejected,
		CollectionFailureUnknown:
		return true
	default:
		return false
	}
}
