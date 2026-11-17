package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	lokiconnector "github.com/Weiki886/relythra/internal/connector/loki"
	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

// PersistLokiEvidence stores one bounded Loki query page against the
// Investigation's canonical service entity.
func (repository *Postgres) PersistLokiEvidence(
	ctx context.Context,
	result lokiconnector.Result,
	meta evidence.LokiEvidenceContext,
	filter *redact.Filter,
) (Evidence, bool, error) {
	if filter == nil {
		return Evidence{}, false, redact.ErrUnsafeOutput
	}
	if !domain.IsID(meta.InvestigationID) || (meta.ToolCallID != "" && !domain.IsID(meta.ToolCallID)) ||
		!domain.IsID(meta.EntityID) || meta.CollectedAt.IsZero() {
		return Evidence{}, false, ErrInvalidInput
	}
	if !strings.EqualFold(meta.EntityType, "SERVICE") {
		return Evidence{}, false, ErrInvalidInput
	}

	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Evidence{}, false, fmt.Errorf("begin Loki evidence: %w", err)
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
		return Evidence{}, false, ErrNotFound
	}
	if err != nil {
		return Evidence{}, false, fmt.Errorf("validate Loki Investigation: %w", err)
	}
	if meta.EntityID != serviceID.String {
		return Evidence{}, false, ErrNotFound
	}

	meta.EntityType = "SERVICE"
	meta.EntityID = serviceID.String
	record, err := evidence.FromLokiResult(ctx, result, meta, filter)
	if err != nil {
		return Evidence{}, false, fmt.Errorf("normalize Loki Evidence: %w", err)
	}
	item, created, err := persistValidatedEvidence(ctx, tx, record)
	if err != nil {
		return Evidence{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Evidence{}, false, fmt.Errorf("commit Loki Evidence: %w", err)
	}
	return item, created, nil
}
