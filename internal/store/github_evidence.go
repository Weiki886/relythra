package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/Weiki886/relythra/internal/connector/github"
	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

// PersistGitHubEvidence stores a bounded GitHub result only when its deployment
// is linked to the Investigation and its commit matches the canonical event.
func (repository *Postgres) PersistGitHubEvidence(
	ctx context.Context,
	result github.Result,
	meta evidence.GitHubEvidenceContext,
	filter *redact.Filter,
) (Evidence, bool, error) {
	if filter == nil {
		return Evidence{}, false, redact.ErrUnsafeOutput
	}
	if !domain.IsID(meta.InvestigationID) || (meta.ToolCallID != "" && !domain.IsID(meta.ToolCallID)) ||
		!domain.IsID(result.DeploymentEventID) || meta.CollectedAt.IsZero() {
		return Evidence{}, false, ErrInvalidInput
	}
	commitSHA, err := hex.DecodeString(result.CommitSHA)
	if err != nil || len(commitSHA) != 20 {
		return Evidence{}, false, ErrInvalidInput
	}

	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Evidence{}, false, fmt.Errorf("begin GitHub evidence: %w", err)
	}
	defer tx.Rollback()

	deployment, err := scanDeploymentEvent(tx.QueryRowContext(ctx, `
		SELECT `+prefixedDeploymentColumns("deployment")+`
		FROM investigations investigation
		JOIN incidents incident ON incident.id=investigation.incident_id
		JOIN deployment_candidates candidate ON candidate.incident_id=incident.id
		JOIN deployment_events deployment ON deployment.id=candidate.deployment_event_id
		WHERE investigation.id=$1
		  AND deployment.id::text=$2
		  AND candidate.project_id=incident.project_id
		  AND deployment.project_id=incident.project_id
		  AND deployment.service_id=investigation.service_id
		  AND deployment.environment=investigation.environment
		  AND candidate.match_status IN ('MATCHED', 'AMBIGUOUS')
		FOR SHARE OF investigation, incident, candidate, deployment
	`, meta.InvestigationID, result.DeploymentEventID))
	if errors.Is(err, sql.ErrNoRows) {
		return Evidence{}, false, ErrNotFound
	}
	if err != nil {
		return Evidence{}, false, fmt.Errorf("validate GitHub deployment ownership: %w", err)
	}
	if !strings.EqualFold(result.CommitSHA, deployment.CommitSHA) {
		return Evidence{}, false, fmt.Errorf("%w: GitHub Commit SHA differs from deployment", ErrConflict)
	}

	meta.EntityType = "SERVICE"
	meta.EntityID = deployment.ServiceID
	record, err := evidence.FromGitHubResult(ctx, result, meta, filter)
	if err != nil {
		return Evidence{}, false, fmt.Errorf("normalize GitHub Evidence: %w", err)
	}
	item, created, err := persistValidatedEvidence(ctx, tx, record)
	if err != nil {
		return Evidence{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Evidence{}, false, fmt.Errorf("commit GitHub evidence: %w", err)
	}
	return item, created, nil
}
