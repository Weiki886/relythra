// Package evidence validates and canonicalizes connector observations before
// they cross into immutable persistence.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/security/redact"
)

const (
	SourceDeployment     = "DEPLOYMENT"
	SourceGitHub         = "GITHUB"
	SourcePrometheus     = "PROMETHEUS"
	SourceLoki           = "LOKI"
	SourceRuntime        = "RUNTIME"
	SourceMapping        = "MAPPING"
	SourceSystem         = "SYSTEM"
	CompletenessComplete = "COMPLETE"
	CompletenessPartial  = "PARTIAL"
	CompletenessMissing  = "MISSING"
	CompletenessExpired  = "EXPIRED"
	maxTextBytes         = 64 * 1024
	maxJSONBytes         = 64 * 1024
)

var ErrInvalidInput = errors.New("invalid evidence input")

type Input struct {
	InvestigationID   string
	ToolCallID        string
	SourceType        string
	EntityType        string
	EntityID          string
	ObservedStart     time.Time
	ObservedEnd       time.Time
	CollectedAt       time.Time
	QueryText         string
	RawReference      string
	QueryParameters   json.RawMessage
	ValueSummary      json.RawMessage
	Completeness      string
	FreshnessSeconds  *int
	IndependenceGroup string
	SourceTimezone    string
	SourceTimeText    string
}

type Record struct {
	InvestigationID   string          `json:"investigation_id"`
	ToolCallID        *string         `json:"tool_call_id"`
	SourceType        string          `json:"source_type"`
	EntityType        string          `json:"entity_type"`
	EntityID          *string         `json:"entity_id"`
	ObservedStart     time.Time       `json:"observed_start"`
	ObservedEnd       time.Time       `json:"observed_end"`
	CollectedAt       time.Time       `json:"collected_at"`
	QueryText         string          `json:"query_text"`
	RawReference      string          `json:"raw_reference"`
	QueryParameters   json.RawMessage `json:"query_parameters"`
	ValueSummary      json.RawMessage `json:"value_summary"`
	Completeness      string          `json:"completeness"`
	FreshnessSeconds  *int            `json:"freshness_seconds"`
	IndependenceGroup string          `json:"independence_group"`
	ContentHash       string          `json:"content_hash"`
	SourceTimezone    string          `json:"source_timezone"`
	SourceTimeText    string          `json:"source_time_text"`
}

type hashPayload struct {
	SourceType        string          `json:"source_type"`
	EntityType        string          `json:"entity_type"`
	EntityID          *string         `json:"entity_id"`
	ObservedStart     time.Time       `json:"observed_start"`
	ObservedEnd       time.Time       `json:"observed_end"`
	QueryText         string          `json:"query_text"`
	RawReference      string          `json:"raw_reference"`
	QueryParameters   json.RawMessage `json:"query_parameters"`
	ValueSummary      json.RawMessage `json:"value_summary"`
	Completeness      string          `json:"completeness"`
	FreshnessSeconds  *int            `json:"freshness_seconds"`
	IndependenceGroup string          `json:"independence_group"`
	SourceTimezone    string          `json:"source_timezone"`
	SourceTimeText    string          `json:"source_time_text"`
}

func Normalize(ctx context.Context, input Input, filter *redact.Filter) (Record, error) {
	if filter == nil {
		return Record{}, redact.ErrUnsafeOutput
	}
	if !domain.IsID(input.InvestigationID) ||
		(input.ToolCallID != "" && !domain.IsID(input.ToolCallID)) ||
		!validSource(input.SourceType) || !validCompleteness(input.Completeness) ||
		domain.ValidateTimeRange(input.ObservedStart, input.ObservedEnd) != nil || input.CollectedAt.IsZero() ||
		strings.TrimSpace(input.EntityType) == "" ||
		input.EntityType != strings.TrimSpace(input.EntityType) ||
		strings.TrimSpace(input.IndependenceGroup) == "" ||
		input.IndependenceGroup != strings.TrimSpace(input.IndependenceGroup) ||
		(input.FreshnessSeconds != nil && *input.FreshnessSeconds < 0) {
		return Record{}, ErrInvalidInput
	}
	if len(input.EntityType) > 128 || len(input.EntityID) > 512 ||
		len(input.QueryText) > maxTextBytes || len(input.RawReference) > maxTextBytes ||
		len(input.IndependenceGroup) > 256 || len(input.SourceTimezone) > 128 ||
		len(input.SourceTimeText) > 256 {
		return Record{}, ErrInvalidInput
	}
	if input.EntityID != "" && input.EntityID != strings.TrimSpace(input.EntityID) {
		return Record{}, ErrInvalidInput
	}
	queryParameters, err := normalizeObject(ctx, filter, input.QueryParameters)
	if err != nil {
		return Record{}, err
	}
	valueSummary, err := normalizeObject(ctx, filter, input.ValueSummary)
	if err != nil {
		return Record{}, err
	}
	clean := func(value string) (string, error) {
		return filter.Text(ctx, value)
	}
	queryText, err := clean(strings.TrimSpace(input.QueryText))
	if err != nil {
		return Record{}, err
	}
	rawReference, err := clean(strings.TrimSpace(input.RawReference))
	if err != nil {
		return Record{}, err
	}
	entityType, err := clean(input.EntityType)
	if err != nil {
		return Record{}, err
	}
	independenceGroup, err := clean(input.IndependenceGroup)
	if err != nil {
		return Record{}, err
	}
	sourceTimezone, err := clean(input.SourceTimezone)
	if err != nil {
		return Record{}, err
	}
	sourceTimeText, err := clean(input.SourceTimeText)
	if err != nil {
		return Record{}, err
	}
	var entityID *string
	if input.EntityID != "" {
		value, err := clean(input.EntityID)
		if err != nil {
			return Record{}, err
		}
		entityID = &value
	}
	var toolCallID *string
	if input.ToolCallID != "" {
		toolCallID = &input.ToolCallID
	}
	record := Record{
		InvestigationID:   input.InvestigationID,
		ToolCallID:        toolCallID,
		SourceType:        input.SourceType,
		EntityType:        entityType,
		EntityID:          entityID,
		ObservedStart:     input.ObservedStart.UTC(),
		ObservedEnd:       input.ObservedEnd.UTC(),
		CollectedAt:       input.CollectedAt.UTC(),
		QueryText:         queryText,
		RawReference:      rawReference,
		QueryParameters:   queryParameters,
		ValueSummary:      valueSummary,
		Completeness:      input.Completeness,
		FreshnessSeconds:  copyInt(input.FreshnessSeconds),
		IndependenceGroup: independenceGroup,
		SourceTimezone:    sourceTimezone,
		SourceTimeText:    sourceTimeText,
	}
	record.ContentHash, err = contentHash(record)
	if err != nil {
		return Record{}, err
	}
	if err := Validate(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func Validate(record Record) error {
	if !domain.IsID(record.InvestigationID) ||
		(record.ToolCallID != nil && !domain.IsID(*record.ToolCallID)) ||
		!validSource(record.SourceType) || !validCompleteness(record.Completeness) ||
		domain.ValidateTimeRange(record.ObservedStart, record.ObservedEnd) != nil || record.CollectedAt.IsZero() ||
		strings.TrimSpace(record.EntityType) == "" || record.EntityType != strings.TrimSpace(record.EntityType) ||
		len(record.EntityType) > 128 || len(record.QueryText) > maxTextBytes || record.QueryText != strings.TrimSpace(record.QueryText) ||
		len(record.RawReference) > maxTextBytes || record.RawReference != strings.TrimSpace(record.RawReference) ||
		strings.TrimSpace(record.IndependenceGroup) == "" || record.IndependenceGroup != strings.TrimSpace(record.IndependenceGroup) ||
		len(record.IndependenceGroup) > 256 || len(record.SourceTimezone) > 128 || len(record.SourceTimeText) > 256 ||
		(record.EntityID != nil && (len(*record.EntityID) > 512 || *record.EntityID != strings.TrimSpace(*record.EntityID))) ||
		(record.FreshnessSeconds != nil && *record.FreshnessSeconds < 0) ||
		!validObject(record.QueryParameters) || !validObject(record.ValueSummary) {
		return ErrInvalidInput
	}
	hash, err := contentHash(record)
	if err != nil || hash != record.ContentHash {
		return ErrInvalidInput
	}
	return nil
}

func validObject(raw json.RawMessage) bool {
	if len(raw) == 0 || len(raw) > maxJSONBytes || !json.Valid(raw) {
		return false
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	_, ok := value.(map[string]any)
	return ok
}

func normalizeObject(ctx context.Context, filter *redact.Filter, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if len(raw) > maxJSONBytes || !json.Valid(raw) {
		return nil, ErrInvalidInput
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, ErrInvalidInput
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, ErrInvalidInput
	}
	redacted, err := filter.JSON(ctx, value)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(redacted)
	if err != nil || len(encoded) > maxJSONBytes {
		return nil, fmt.Errorf("%w: JSON object cannot be canonicalized", ErrInvalidInput)
	}
	return encoded, nil
}

func contentHash(record Record) (string, error) {
	payload := hashPayload{
		SourceType: record.SourceType, EntityType: record.EntityType, EntityID: record.EntityID,
		ObservedStart: record.ObservedStart.UTC(), ObservedEnd: record.ObservedEnd.UTC(),
		QueryText: record.QueryText, RawReference: record.RawReference,
		QueryParameters: record.QueryParameters, ValueSummary: record.ValueSummary,
		Completeness: record.Completeness, FreshnessSeconds: record.FreshnessSeconds,
		IndependenceGroup: record.IndependenceGroup, SourceTimezone: record.SourceTimezone,
		SourceTimeText: record.SourceTimeText,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal evidence hash payload: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validSource(source string) bool {
	switch source {
	case SourceDeployment, SourceGitHub, SourcePrometheus, SourceLoki, SourceRuntime, SourceMapping, SourceSystem:
		return true
	default:
		return false
	}
}

func validCompleteness(value string) bool {
	switch value {
	case CompletenessComplete, CompletenessPartial, CompletenessMissing, CompletenessExpired:
		return true
	default:
		return false
	}
}

func copyInt(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
