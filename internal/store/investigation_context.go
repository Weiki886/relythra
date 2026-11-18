package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Weiki886/relythra/internal/domain"
)

// ContextEntity is a display identity, without configuration or credentials.
type ContextEntity struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type ContextAlert struct {
	ID              string     `json:"id"`
	Status          string     `json:"status"`
	Severity        string     `json:"severity"`
	Summary         string     `json:"summary"`
	StartsAt        time.Time  `json:"starts_at"`
	EndsAt          *time.Time `json:"ends_at"`
	SourceReference string     `json:"source_reference"`
}

// InvestigationContext is current registration state, not an Evidence snapshot.
type InvestigationContext struct {
	InvestigationID string                     `json:"investigation_id"`
	IncidentID      string                     `json:"incident_id"`
	Status          domain.InvestigationStatus `json:"status"`
	StartedAt       time.Time                  `json:"started_at"`
	CompletedAt     *time.Time                 `json:"completed_at"`
	Project         ContextEntity              `json:"project"`
	Service         *ContextEntity             `json:"service"`
	Environment     *string                    `json:"environment"`
	Alert           *ContextAlert              `json:"alert"`
	MappingStatus   string                     `json:"mapping_status"`
	ContextGaps     []string                   `json:"context_gaps"`
}

func (repository *Postgres) GetInvestigationContext(ctx context.Context, id string) (InvestigationContext, error) {
	if !domain.IsID(id) {
		return InvestigationContext{}, fmt.Errorf("%w: invalid investigation UUID", ErrInvalidInput)
	}
	var result InvestigationContext
	var completedAt, alertStart, alertEnd sql.NullTime
	var serviceID, serviceSlug, serviceName, environment sql.NullString
	var alertID, alertStatus, severity, summary, reference sql.NullString
	var consistent bool
	// One statement keeps ownership and current alert facts in the same MVCC snapshot.
	err := repository.db.QueryRowContext(ctx, `
		SELECT i.id::text, i.incident_id::text, i.status, i.started_at, i.completed_at,
			p.id::text, p.slug, p.name, s.id::text, s.slug, s.name, i.environment,
			a.id::text, a.status, a.severity, a.summary, a.starts_at, a.ends_at, a.source_reference,
			(i.service_id IS NOT DISTINCT FROM inc.service_id
			 AND i.environment IS NOT DISTINCT FROM inc.environment
			 AND (i.service_id IS NULL OR s.id IS NOT NULL)
			 AND (inc.alert_id IS NULL OR (a.id IS NOT NULL
				 AND a.service_id IS NOT DISTINCT FROM i.service_id
				 AND a.environment IS NOT DISTINCT FROM i.environment)))
		FROM investigations i
		JOIN incidents inc ON inc.id=i.incident_id
		JOIN projects p ON p.id=inc.project_id
		LEFT JOIN services s ON s.id=i.service_id AND s.project_id=inc.project_id
		LEFT JOIN alerts a ON a.id=inc.alert_id AND a.project_id=inc.project_id
		WHERE i.id=$1
	`, id).Scan(
		&result.InvestigationID, &result.IncidentID, &result.Status, &result.StartedAt, &completedAt,
		&result.Project.ID, &result.Project.Slug, &result.Project.Name, &serviceID, &serviceSlug, &serviceName, &environment,
		&alertID, &alertStatus, &severity, &summary, &alertStart, &alertEnd, &reference, &consistent,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return InvestigationContext{}, ErrNotFound
	}
	if err != nil {
		return InvestigationContext{}, fmt.Errorf("read investigation context: %w", err)
	}
	result.CompletedAt = nullTimePointer(completedAt)
	result.ContextGaps = []string{}
	if alertID.Valid {
		result.Alert = &ContextAlert{
			ID: alertID.String, Status: alertStatus.String, Severity: severity.String, Summary: summary.String,
			StartsAt: alertStart.Time, EndsAt: nullTimePointer(alertEnd), SourceReference: reference.String,
		}
	} else {
		result.ContextGaps = append(result.ContextGaps, "alert_not_linked")
	}
	if !consistent {
		result.MappingStatus = "CONFLICT"
		result.ContextGaps = append(result.ContextGaps, "mapping_conflict")
		return result, nil
	}
	result.MappingStatus = "MATCHED"
	if serviceID.Valid {
		result.Service = &ContextEntity{ID: serviceID.String, Slug: serviceSlug.String, Name: serviceName.String}
	} else {
		result.MappingStatus = "NEEDS_MAPPING"
		result.ContextGaps = append(result.ContextGaps, "service_mapping_missing")
	}
	result.Environment = nullStringPointer(environment)
	if !environment.Valid || environment.String == "" {
		result.Environment = nil
		result.MappingStatus = "NEEDS_MAPPING"
		result.ContextGaps = append(result.ContextGaps, "environment_mapping_missing")
	}
	return result, nil
}
