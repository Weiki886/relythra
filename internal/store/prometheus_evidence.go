package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

// PersistPrometheusEvidence stores a bounded Prometheus result against the
// Investigation's canonical service entity.
func (repository *Postgres) PersistPrometheusEvidence(
	ctx context.Context,
	result prometheusconnector.Result,
	meta evidence.PrometheusEvidenceContext,
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
		return Evidence{}, false, fmt.Errorf("begin Prometheus evidence: %w", err)
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
		return Evidence{}, false, fmt.Errorf("validate Prometheus Investigation: %w", err)
	}
	if meta.EntityID != "" && meta.EntityID != serviceID.String {
		return Evidence{}, false, ErrNotFound
	}

	meta.EntityType = "SERVICE"
	meta.EntityID = serviceID.String
	record, err := evidence.FromPrometheusResult(ctx, result, meta, filter)
	if err != nil {
		return Evidence{}, false, fmt.Errorf("normalize Prometheus Evidence: %w", err)
	}
	item, created, err := persistValidatedEvidence(ctx, tx, record)
	if err != nil {
		return Evidence{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Evidence{}, false, fmt.Errorf("commit Prometheus Evidence: %w", err)
	}
	return item, created, nil
}
