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
	Stance       string
}

type InvestigationTimeline struct {
	InvestigationID string                      `json:"investigation_id"`
	Items           []InvestigationTimelineItem `json:"items"`
	Total           int                         `json:"total"`
	Limit           int                         `json:"limit"`
	Offset          int                         `json:"offset"`
	HasMore         bool                        `json:"has_more"`
}

type InvestigationTimelineItem struct {
	Evidence
	Relations []EvidenceRelation `json:"relations"`
}

type EvidenceRelation struct {
	HypothesisID string `json:"hypothesis_id"`
	Stance       string `json:"stance"`
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

	items := make([]InvestigationTimelineItem, 0, limit)
	for rows.Next() {
		item, err := scanEvidence(rows)
		if err != nil {
			return InvestigationTimeline{}, fmt.Errorf("scan investigation timeline evidence: %w", err)
		}
		items = append(items, InvestigationTimelineItem{Evidence: item})
	}
	if err := rows.Err(); err != nil {
		return InvestigationTimeline{}, fmt.Errorf("iterate investigation timeline evidence: %w", err)
	}
	if err := rows.Close(); err != nil {
		return InvestigationTimeline{}, fmt.Errorf("close investigation timeline evidence: %w", err)
	}
	if err := loadTimelineEvidenceRelations(ctx, tx, investigationID, items); err != nil {
		return InvestigationTimeline{}, err
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

func loadTimelineEvidenceRelations(
	ctx context.Context,
	tx *sql.Tx,
	investigationID string,
	items []InvestigationTimelineItem,
) error {
	if len(items) == 0 {
		return nil
	}
	arguments := make([]any, 1, len(items)+1)
	arguments[0] = investigationID
	placeholders := make([]string, 0, len(items))
	relationsByEvidence := make(map[string][]EvidenceRelation, len(items))
	for index, item := range items {
		arguments = append(arguments, item.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", index+2))
		relationsByEvidence[item.ID] = []EvidenceRelation{}
	}
	query := `SELECT evidence_id::text, hypothesis_id::text, stance
		FROM hypothesis_evidence
		WHERE investigation_id = $1 AND evidence_id IN (` + strings.Join(placeholders, ", ") + `)
		ORDER BY evidence_id, hypothesis_id, stance`
	rows, err := tx.QueryContext(ctx, query, arguments...)
	if err != nil {
		return fmt.Errorf("read investigation timeline evidence relations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var evidenceID string
		var relation EvidenceRelation
		if err := rows.Scan(&evidenceID, &relation.HypothesisID, &relation.Stance); err != nil {
			return fmt.Errorf("scan investigation timeline evidence relation: %w", err)
		}
		relationsByEvidence[evidenceID] = append(relationsByEvidence[evidenceID], relation)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate investigation timeline evidence relations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close investigation timeline evidence relations: %w", err)
	}
	for index := range items {
		items[index].Relations = relationsByEvidence[items[index].ID]
	}
	return nil
}

func ValidateInvestigationTimelineFilter(filter InvestigationTimelineFilter) error {
	if filter.SourceType != "" {
		switch filter.SourceType {
		case "DEPLOYMENT", "GRAFANA", "GITHUB", "PROMETHEUS", "LOKI", "RUNTIME", "MAPPING", "SYSTEM":
		default:
			return fmt.Errorf("%w: invalid timeline source type", ErrInvalidInput)
		}
	}
	if filter.Completeness != "" {
		switch filter.Completeness {
		case "COMPLETE", "PARTIAL", "MISSING", "EXPIRED":
		default:
			return fmt.Errorf("%w: invalid timeline completeness", ErrInvalidInput)
		}
	}
	if filter.Stance != "" && filter.Stance != "SUPPORTS" && filter.Stance != "CONTRADICTS" {
		return fmt.Errorf("%w: invalid timeline stance", ErrInvalidInput)
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
	if filter.Stance != "" {
		arguments = append(arguments, filter.Stance)
		conditions = append(conditions, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM hypothesis_evidence he
			WHERE he.investigation_id = evidence.investigation_id
			  AND he.evidence_id = evidence.id AND he.stance = $%d
		)`, len(arguments)))
	}
	return " WHERE " + strings.Join(conditions, " AND "), arguments
}
