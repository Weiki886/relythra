package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Weiki886/relythra/internal/domain"
)

const (
	EvidenceStanceSupports    = "SUPPORTS"
	EvidenceStanceContradicts = "CONTRADICTS"
)

// AddEvidenceRelation appends an immutable hypothesis-to-evidence relation.
// Replaying the same relation is idempotent and reports created=false.
func (repository *Postgres) AddEvidenceRelation(
	ctx context.Context,
	investigationID string,
	hypothesisID string,
	evidenceID string,
	stance string,
) (bool, error) {
	if !domain.IsID(investigationID) || !domain.IsID(hypothesisID) || !domain.IsID(evidenceID) ||
		(stance != EvidenceStanceSupports && stance != EvidenceStanceContradicts) {
		return false, fmt.Errorf("%w: evidence relation is invalid", ErrInvalidInput)
	}
	if repository == nil || repository.db == nil {
		return false, errors.New("evidence relation repository is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var created bool
	err := repository.db.QueryRowContext(ctx, `
		INSERT INTO hypothesis_evidence (investigation_id, hypothesis_id, evidence_id, stance)
		SELECT $1, $2, $3, $4
		WHERE EXISTS (
			SELECT 1
			FROM hypotheses h
			JOIN evidence e ON e.investigation_id = h.investigation_id
			WHERE h.id = $2 AND e.id = $3 AND h.investigation_id = $1
		)
		ON CONFLICT (hypothesis_id, evidence_id, stance) DO NOTHING
		RETURNING true
	`, investigationID, hypothesisID, evidenceID, stance).Scan(&created)
	if err == nil {
		return created, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("append evidence relation: %w", err)
	}
	var matchingInvestigation bool
	if err := repository.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM hypotheses h
			JOIN evidence e ON e.investigation_id = h.investigation_id
			WHERE h.id = $2 AND e.id = $3 AND h.investigation_id = $1
		)
	`, investigationID, hypothesisID, evidenceID).Scan(&matchingInvestigation); err != nil {
		return false, fmt.Errorf("check evidence relation owner: %w", err)
	}
	if !matchingInvestigation {
		return false, ErrNotFound
	}
	return false, nil
}
