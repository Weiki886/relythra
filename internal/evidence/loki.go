package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/connector/loki"
	"github.com/Weiki886/relythra/internal/security/redact"
)

// LokiEvidenceContext supplies investigation ownership omitted by the connector result.
type LokiEvidenceContext struct {
	InvestigationID string
	ToolCallID      string
	EntityType      string
	EntityID        string
	CollectedAt     time.Time
}

type lokiQueryParameters struct {
	TemplateID      string `json:"template_id"`
	TemplateVersion int    `json:"template_version"`
	Direction       string `json:"direction"`
	Severity        string `json:"severity"`
	Limit           int    `json:"limit"`
	ResponseSHA256  string `json:"response_sha256"`
}

type lokiValueSummary struct {
	Entries  []loki.Entry `json:"entries"`
	Warnings []string     `json:"warnings"`
	HasMore  bool         `json:"has_more"`
	Empty    bool         `json:"empty"`
	Partial  bool         `json:"partial"`
	TimeSkew bool         `json:"time_skew"`
}

// FromLokiResult turns one query page into Evidence. A continuation, clipped log
// or unreliable timestamp makes the evidence partial, even if the page is empty.
// Oversized pages fail the normalizer's bounds without silently dropping logs.
func FromLokiResult(
	ctx context.Context,
	result loki.Result,
	metadata LokiEvidenceContext,
	filter *redact.Filter,
) (Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if filter == nil {
		return Record{}, redact.ErrUnsafeOutput
	}
	if strings.TrimSpace(result.TemplateID) == "" || result.TemplateVersion <= 0 || strings.TrimSpace(result.Query) == "" ||
		strings.TrimSpace(result.SourceReference) == "" ||
		(result.Direction != "forward" && result.Direction != "backward") || result.Limit <= 0 {
		return Record{}, ErrInvalidInput
	}
	queryParameters, err := json.Marshal(lokiQueryParameters{
		TemplateID: result.TemplateID, TemplateVersion: result.TemplateVersion,
		Direction: result.Direction, Severity: result.Severity, Limit: result.Limit,
		ResponseSHA256: result.ResponseSHA256,
	})
	if err != nil {
		return Record{}, fmt.Errorf("%w: encode Loki query metadata", ErrInvalidInput)
	}
	entries := make([]loki.Entry, len(result.Entries))
	partial := result.Partial || len(result.Warnings) > 0 || result.NextCursor != "" || result.TimeSkew
	skew := result.TimeSkew
	var latest time.Time
	for index, entry := range result.Entries {
		if entry.Timestamp.IsZero() || entry.Line.Trust != "untrusted_data" || entry.Line.Source != "loki" {
			return Record{}, ErrInvalidInput
		}
		entry.Timestamp = entry.Timestamp.UTC()
		entries[index] = entry
		partial = partial || entry.OutsideTimeWindow || entry.Line.Truncated
		skew = skew || entry.OutsideTimeWindow
		if entry.Timestamp.After(latest) {
			latest = entry.Timestamp
		}
	}
	warnings := result.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	valueSummary, err := json.Marshal(lokiValueSummary{
		Entries: entries, Warnings: warnings, HasMore: result.NextCursor != "",
		Empty: result.Empty, Partial: result.Partial, TimeSkew: result.TimeSkew,
	})
	if err != nil {
		return Record{}, fmt.Errorf("%w: encode Loki result", ErrInvalidInput)
	}
	partial = partial || latest.After(metadata.CollectedAt)
	completeness := CompletenessComplete
	switch {
	case partial:
		completeness = CompletenessPartial
	case len(entries) == 0:
		completeness = CompletenessMissing
	}
	var freshnessSeconds *int
	if !skew && !latest.IsZero() && !latest.After(metadata.CollectedAt) {
		age := int(metadata.CollectedAt.Sub(latest) / time.Second)
		freshnessSeconds = &age
	}
	return Normalize(ctx, Input{
		InvestigationID: metadata.InvestigationID, ToolCallID: metadata.ToolCallID,
		SourceType: SourceLoki, EntityType: metadata.EntityType, EntityID: metadata.EntityID,
		ObservedStart: result.Start, ObservedEnd: result.End, CollectedAt: metadata.CollectedAt,
		QueryText: result.Query, RawReference: result.SourceReference,
		QueryParameters: queryParameters, ValueSummary: valueSummary,
		Completeness: completeness, FreshnessSeconds: freshnessSeconds,
		IndependenceGroup: fmt.Sprintf("loki:%s:v%d", result.TemplateID, result.TemplateVersion),
		SourceTimezone:    "UTC",
		SourceTimeText:    result.Start.UTC().Format(time.RFC3339Nano) + "/" + result.End.UTC().Format(time.RFC3339Nano),
	}, filter)
}
