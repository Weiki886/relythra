package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/Weiki886/relythra/internal/domain"
)

const (
	maxInvestigationTimelinePageSize = 100
	maxInvestigationTimelineOffset   = 10000
	maxInvestigationTimelineEntityID = 256
)

type InvestigationTimelineFilter struct {
	SourceType   string
	EntityID     string
	Completeness string
}

type InvestigationTimeline struct {
	InvestigationID string     `json:"investigation_id"`
	Items           []Evidence `json:"items"`
	Total           int        `json:"total"`
	Limit           int        `json:"limit"`
	Offset          int        `json:"offset"`
	HasMore         bool       `json:"has_more"`
}

func (repository *Postgres) GetInvestigationTimeline(
	ctx context.Context,
	investigationID string,
	filter InvestigationTimelineFilter,
	limit int,
	offset int,
) (InvestigationTimeline, error) {
	if !domain.IsID(investigationID) || limit < 1 ||
		limit > maxInvestigationTimelinePageSize || offset < 0 ||
		offset > maxInvestigationTimelineOffset ||
		ValidateInvestigationTimelineFilter(filter) != nil {
		return InvestigationTimeline{}, fmt.Errorf("%w: investigation timeline query is invalid", ErrInvalidInput)
	}

	where, arguments := investigationTimelineWhere(investigationID, filter)
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return InvestigationTimeline{}, fmt.Errorf("begin investigation timeline read: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var investigationExists bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM investigations WHERE id = $1)
	`, investigationID).Scan(&investigationExists); err != nil {
		return InvestigationTimeline{}, fmt.Errorf("check investigation timeline owner: %w", err)
	}
	if !investigationExists {
		return InvestigationTimeline{}, ErrNotFound
	}

	var total int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM evidence"+where, arguments...).Scan(&total); err != nil {
		return InvestigationTimeline{}, fmt.Errorf("count investigation timeline evidence: %w", err)
	}

	pageArguments := append(append([]any(nil), arguments...), limit, offset)
	rows, err := tx.QueryContext(ctx, `
		SELECT `+evidenceColumns+`
		FROM evidence`+where+fmt.Sprintf(
		" ORDER BY observed_start, observed_end, source_type, entity_type, COALESCE(entity_id, ''), content_hash, id LIMIT $%d OFFSET $%d",
		len(pageArguments)-1,
		len(pageArguments),
	), pageArguments...)
	if err != nil {
		return InvestigationTimeline{}, fmt.Errorf("read investigation timeline evidence: %w", err)
	}
	defer rows.Close()

	items := make([]Evidence, 0, limit)
	for rows.Next() {
		evidence, err := scanEvidence(rows)
		if err != nil {
			return InvestigationTimeline{}, fmt.Errorf("scan investigation timeline evidence: %w", err)
		}
		items = append(items, evidence)
	}
	if err := rows.Err(); err != nil {
		return InvestigationTimeline{}, fmt.Errorf("iterate investigation timeline evidence: %w", err)
	}
	if err := rows.Close(); err != nil {
		return InvestigationTimeline{}, fmt.Errorf("close investigation timeline evidence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return InvestigationTimeline{}, fmt.Errorf("commit investigation timeline read: %w", err)
	}
	return InvestigationTimeline{
		InvestigationID: investigationID,
		Items:           items,
		Total:           total,
		Limit:           limit,
		Offset:          offset,
		HasMore:         offset+len(items) < total,
	}, nil
}

func ValidateInvestigationTimelineFilter(filter InvestigationTimelineFilter) error {
	if filter.SourceType != "" {
		switch filter.SourceType {
		case "DEPLOYMENT", "GITHUB", "PROMETHEUS", "LOKI", "RUNTIME", "MAPPING", "SYSTEM":
		default:
			return fmt.Errorf("%w: invalid timeline source type", ErrInvalidInput)
		}
	}
	if filter.Completeness != "" {
		switch filter.Completeness {
		case "COMPLETE", "PARTIAL", "MISSING":
		default:
			return fmt.Errorf("%w: invalid timeline completeness", ErrInvalidInput)
		}
	}
	if filter.EntityID != strings.TrimSpace(filter.EntityID) ||
		len(filter.EntityID) > maxInvestigationTimelineEntityID {
		return fmt.Errorf("%w: invalid timeline entity ID", ErrInvalidInput)
	}
	return nil
}

func investigationTimelineWhere(
	investigationID string,
	filter InvestigationTimelineFilter,
) (string, []any) {
	conditions := []string{"investigation_id = $1"}
	arguments := []any{investigationID}
	if filter.SourceType != "" {
		arguments = append(arguments, filter.SourceType)
		conditions = append(conditions, fmt.Sprintf("source_type = $%d", len(arguments)))
	}
	if filter.EntityID != "" {
		arguments = append(arguments, filter.EntityID)
		conditions = append(conditions, fmt.Sprintf("entity_id = $%d", len(arguments)))
	}
	if filter.Completeness != "" {
		arguments = append(arguments, filter.Completeness)
		conditions = append(conditions, fmt.Sprintf("completeness = $%d", len(arguments)))
	}
	return " WHERE " + strings.Join(conditions, " AND "), arguments
}
