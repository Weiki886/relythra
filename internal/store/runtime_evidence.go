package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	runtimeconnector "github.com/Weiki886/relythra/internal/connector/runtime"
	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

// RuntimeEvidencePersistenceContext binds a runtime result to the service and
// Investigation that authorized its collection.
type RuntimeEvidencePersistenceContext struct {
	InvestigationID string
	ServiceID       string
	ToolCallID      string
	CollectedAt     time.Time
}

// PersistRuntimeEvidence normalizes and stores one bounded runtime result as an
// atomic Evidence batch after validating the Investigation's service ownership.
func (repository *Postgres) PersistRuntimeEvidence(
	ctx context.Context,
	result runtimeconnector.Result,
	meta RuntimeEvidencePersistenceContext,
	filter *redact.Filter,
) ([]Evidence, []bool, error) {
	if filter == nil {
		return nil, nil, redact.ErrUnsafeOutput
	}
	if !domain.IsID(meta.InvestigationID) || !domain.IsID(meta.ServiceID) ||
		(meta.ToolCallID != "" && !domain.IsID(meta.ToolCallID)) || meta.CollectedAt.IsZero() {
		return nil, nil, ErrInvalidInput
	}

	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin runtime Evidence batch: %w", err)
	}
	defer tx.Rollback()

	var serviceID sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT service_id::text
		FROM investigations
		WHERE id = $1
		FOR SHARE
	`, meta.InvestigationID).Scan(&serviceID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !serviceID.Valid) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("validate runtime Investigation: %w", err)
	}
	if meta.ServiceID != serviceID.String {
		return nil, nil, ErrNotFound
	}

	records, err := evidence.FromRuntimeResult(ctx, result, evidence.RuntimeEvidenceContext{
		InvestigationID: meta.InvestigationID,
		ToolCallID:      meta.ToolCallID,
		CollectedAt:     meta.CollectedAt,
	}, filter)
	if err != nil {
		return nil, nil, fmt.Errorf("normalize runtime Evidence: %w", err)
	}
	if len(records) > maxEvidenceBatchSize {
		return nil, nil, fmt.Errorf("%w: runtime Evidence batch exceeds %d records", ErrInvalidInput, maxEvidenceBatchSize)
	}

	items := make([]Evidence, 0, len(records))
	created := make([]bool, 0, len(records))
	for _, record := range records {
		if record.InvestigationID != meta.InvestigationID {
			return nil, nil, fmt.Errorf("%w: runtime Evidence batch spans multiple investigations", ErrInvalidInput)
		}
		item, inserted, err := persistValidatedEvidence(ctx, tx, record)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, item)
		created = append(created, inserted)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit runtime Evidence batch: %w", err)
	}
	return items, created, nil
}
