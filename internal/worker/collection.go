package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/security/secrets"
	"github.com/Weiki886/relythra/internal/store"
)

const (
	collectionLease     = 10 * time.Minute
	collectionRetryBase = 5 * time.Second
	collectionLookback  = 5 * time.Minute
	collectionLookahead = 5 * time.Minute
	collectionQueryStep = 2 * time.Minute
	collectionMaxSeries = 2
	collectionMaxPoints = int(datasource.MaxQueryWindow/collectionQueryStep) + 1
)

var (
	errCollectionRetryScheduled = errors.New("collection task scheduled for retry")
	errCollectionRetryFailed    = errors.New("collection retry state could not be saved")
	errCollectionLeaseLost      = errors.New("collection task lease is no longer active")
)

type collectionRepository interface {
	ClaimInvestigationCollectionJobs(context.Context, int, time.Duration) ([]store.InvestigationCollectionJob, error)
	GetInvestigationContext(context.Context, string) (store.InvestigationContext, error)
	ListDataSourceMappings(context.Context, string, string, string) ([]store.DataSourceMapping, error)
	PersistPrometheusEvidence(context.Context, prometheusconnector.Result, evidence.PrometheusEvidenceContext, *redact.Filter) (store.Evidence, bool, error)
	PersistEvidence(context.Context, evidence.Record) (store.Evidence, bool, error)
	CompleteInvestigationCollectionJob(context.Context, string, string) (bool, error)
	RetryInvestigationCollectionJob(context.Context, string, string, string, time.Duration) (bool, error)
}

type prometheusQueryer interface {
	Query(context.Context, prometheusconnector.Target, datasource.NormalizedQuery) (prometheusconnector.Result, error)
}

type CollectionOptions struct {
	Now        func() time.Time
	RetryDelay func(attempt int) time.Duration
}

type CollectionProcessor struct {
	repository collectionRepository
	connector  prometheusQueryer
	resolver   prometheusconnector.SecretResolver
	filter     *redact.Filter
	now        func() time.Time
	retryDelay func(int) time.Duration
}

func NewCollectionProcessor(
	repository collectionRepository,
	connector prometheusQueryer,
	resolver prometheusconnector.SecretResolver,
	filter *redact.Filter,
	options CollectionOptions,
) (*CollectionProcessor, error) {
	if repository == nil || connector == nil || resolver == nil || filter == nil {
		return nil, errors.New("collection repository, connector, secret resolver, and redaction filter are required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.RetryDelay == nil {
		options.RetryDelay = func(attempt int) time.Duration {
			delay := collectionRetryBase << max(0, min(attempt-1, 8))
			return min(delay, time.Hour)
		}
	}
	return &CollectionProcessor{
		repository: repository,
		connector:  connector,
		resolver:   resolver,
		filter:     filter,
		now:        options.Now,
		retryDelay: options.RetryDelay,
	}, nil
}

// Process claims no work itself; it handles exactly one previously claimed job.
// It persists a result or explicit gap before acknowledging the lease.
func (processor *CollectionProcessor) Process(ctx context.Context, job store.InvestigationCollectionJob) error {
	if processor == nil || ctx == nil || job.ID == "" || job.InvestigationID == "" || job.LeaseToken == "" || job.AttemptCount < 1 {
		return errors.New("collection task claim is invalid")
	}
	investigation, err := processor.repository.GetInvestigationContext(ctx, job.InvestigationID)
	if err != nil || investigation.InvestigationID != job.InvestigationID || investigation.MappingStatus != "MATCHED" ||
		investigation.Service == nil || investigation.Environment == nil || investigation.Alert == nil {
		return processor.retry(ctx, job, "investigation_context_unavailable")
	}
	windowStart, windowEnd, ok := collectionWindow(investigation.Alert, processor.now())
	if !ok {
		return processor.retry(ctx, job, "investigation_context_unavailable")
	}
	mappings, err := processor.repository.ListDataSourceMappings(ctx, investigation.Project.ID, investigation.Service.ID, *investigation.Environment)
	if err != nil {
		return processor.retry(ctx, job, "mapping_read_failed")
	}
	for _, mapping := range mappings {
		if mapping.ProjectID != investigation.Project.ID || mapping.ServiceID != investigation.Service.ID || mapping.Environment != *investigation.Environment {
			return processor.retry(ctx, job, "mapping_scope_conflict")
		}
	}

	prometheusMappings := 0
	retryCode := ""
	for _, mapping := range mappings {
		switch mapping.SourceType {
		case datasource.SourcePrometheus:
			prometheusMappings++
			if err := processor.collectPrometheus(ctx, job, investigation, mapping, windowStart, windowEnd); err != nil {
				var failure *collectionFailure
				if errors.As(err, &failure) {
					if retryCode == "" {
						retryCode = failure.code
					}
					continue
				}
				return processor.retry(ctx, job, "evidence_persist_failed")
			}
		case datasource.SourceLoki, datasource.SourceGitHub, datasource.SourceRuntime:
			if err := processor.persistUnsupportedGaps(ctx, job, investigation, mapping, windowStart, windowEnd); err != nil {
				return processor.retry(ctx, job, "gap_persist_failed")
			}
		case datasource.SourceGrafana:
			// Grafana mappings describe alert metadata; alert context is already persisted.
		default:
			return processor.retry(ctx, job, "mapping_source_unsupported")
		}
	}
	if prometheusMappings == 0 {
		if err := processor.persistMissingPrometheusGap(ctx, job, investigation, windowStart, windowEnd); err != nil {
			return processor.retry(ctx, job, "gap_persist_failed")
		}
	}
	if retryCode != "" {
		return processor.retry(ctx, job, retryCode)
	}
	completed, err := processor.repository.CompleteInvestigationCollectionJob(ctx, job.ID, job.LeaseToken)
	if err != nil {
		return errors.New("collection task completion failed")
	}
	if !completed {
		return errCollectionLeaseLost
	}
	return nil
}

func (processor *CollectionProcessor) collectPrometheus(
	ctx context.Context,
	job store.InvestigationCollectionJob,
	investigation store.InvestigationContext,
	mapping store.DataSourceMapping,
	start time.Time,
	end time.Time,
) error {
	if len(mapping.Templates) == 0 {
		return &collectionFailure{code: "prometheus_template_missing"}
	}
	ids := make([]string, 0, len(mapping.Templates))
	for _, template := range mapping.Templates {
		ids = append(ids, template.ID)
	}
	templates, issues := datasource.ResolveTemplates(datasource.SourcePrometheus, ids)
	if len(issues) > 0 || len(templates) != len(mapping.Templates) {
		return &collectionFailure{code: "prometheus_template_invalid"}
	}
	secretReference, err := parseSecretReference(mapping.SecretRef)
	if err != nil {
		return &collectionFailure{code: "prometheus_secret_reference_invalid"}
	}
	retryCode := ""
	for index, template := range templates {
		if template.Version != mapping.Templates[index].Version {
			if err := processor.persistGap(ctx, job, investigation, string(datasource.SourcePrometheus), template.ID, template.Version, evidence.CollectionFailureRequestRejected, start, end); err != nil {
				return &collectionFailure{code: "gap_persist_failed"}
			}
			continue
		}
		query, issues := datasource.ValidateQuery(template, datasource.QueryParameters{
			Service: investigation.Service.Slug, Environment: *investigation.Environment,
			QueryType: datasource.QueryTypeRange, Start: start.Format(time.RFC3339Nano), End: end.Format(time.RFC3339Nano),
			Step: collectionQueryStep.String(), MaxSeries: collectionMaxSeries, MaxPoints: collectionMaxPoints,
		})
		if len(issues) > 0 {
			if err := processor.persistGap(ctx, job, investigation, string(datasource.SourcePrometheus), template.ID, template.Version, evidence.CollectionFailureRequestRejected, start, end); err != nil {
				return &collectionFailure{code: "gap_persist_failed"}
			}
			if retryCode == "" {
				retryCode = "prometheus_query_invalid"
			}
			continue
		}
		var resolvedSecret *secrets.Secret
		queryFilter := processor.filter
		if secretReference != nil {
			secret, err := processor.resolver.Resolve(ctx, *secretReference)
			if err != nil {
				if gapErr := processor.persistGap(ctx, job, investigation, string(datasource.SourcePrometheus), template.ID, template.Version, evidence.CollectionFailurePermissionDenied, start, end); gapErr != nil {
					return &collectionFailure{code: "gap_persist_failed"}
				}
				if retryCode == "" {
					retryCode = "prometheus_secret_unavailable"
				}
				continue
			}
			resolvedSecret = &secret
			queryFilter, err = processor.filter.WithAdditionalSecrets(secret.Reveal())
			if err != nil {
				return &collectionFailure{code: "evidence_persist_failed"}
			}
		}
		result, err := processor.connector.Query(ctx, prometheusconnector.Target{
			Endpoint: mapping.PublicSettings.Endpoint, SecretReference: secretReference, ResolvedSecret: resolvedSecret,
		}, query)
		if err != nil {
			code := collectionErrorCode(err)
			reason := collectionReasonCode(err)
			if gapErr := processor.persistGap(ctx, job, investigation, string(datasource.SourcePrometheus), template.ID, template.Version, reason, start, end); gapErr != nil {
				return &collectionFailure{code: "gap_persist_failed"}
			}
			if retryCode == "" {
				retryCode = code
			}
			continue
		}
		if result.TemplateID != template.ID || result.TemplateVersion != template.Version || result.QueryType != datasource.QueryTypeRange ||
			!result.End.After(result.Start) || result.End.Sub(result.Start) > datasource.MaxQueryWindow {
			if err := processor.persistGap(ctx, job, investigation, string(datasource.SourcePrometheus), template.ID, template.Version, evidence.CollectionFailureInvalidResponse, start, end); err != nil {
				return &collectionFailure{code: "gap_persist_failed"}
			}
			if retryCode == "" {
				retryCode = "prometheus_result_invalid"
			}
			continue
		}
		if _, _, err := processor.repository.PersistPrometheusEvidence(ctx, result, evidence.PrometheusEvidenceContext{
			InvestigationID: job.InvestigationID, EntityType: "SERVICE", EntityID: investigation.Service.ID, CollectedAt: processor.now().UTC(),
		}, queryFilter); err != nil {
			return &collectionFailure{code: "evidence_persist_failed"}
		}
	}
	if retryCode != "" {
		return &collectionFailure{code: retryCode}
	}
	return nil
}

func (processor *CollectionProcessor) persistUnsupportedGaps(
	ctx context.Context,
	job store.InvestigationCollectionJob,
	investigation store.InvestigationContext,
	mapping store.DataSourceMapping,
	start time.Time,
	end time.Time,
) error {
	if len(mapping.Templates) == 0 {
		return fmt.Errorf("unsupported source mapping has no templates")
	}
	templates, issues := datasource.ResolveTemplates(mapping.SourceType, templateIDs(mapping.Templates))
	if len(issues) > 0 || len(templates) != len(mapping.Templates) {
		return fmt.Errorf("unsupported source mapping template is invalid")
	}
	for _, template := range templates {
		if err := processor.persistGap(ctx, job, investigation, string(mapping.SourceType), template.ID, template.Version, evidence.CollectionFailureUnsupported, start, end); err != nil {
			return err
		}
	}
	return nil
}

func (processor *CollectionProcessor) persistMissingPrometheusGap(
	ctx context.Context,
	job store.InvestigationCollectionJob,
	investigation store.InvestigationContext,
	start time.Time,
	end time.Time,
) error {
	return processor.persistGap(ctx, job, investigation, string(datasource.SourcePrometheus), "prometheus.service.latency.v1", 1, evidence.CollectionFailureMissingMapping, start, end)
}

func (processor *CollectionProcessor) persistGap(
	ctx context.Context,
	job store.InvestigationCollectionJob,
	investigation store.InvestigationContext,
	source, templateID string,
	templateVersion int,
	reason evidence.CollectionFailureCode,
	start time.Time,
	end time.Time,
) error {
	record, err := evidence.FromCollectionFailure(ctx, evidence.CollectionGapInput{
		InvestigationID: job.InvestigationID, SourceType: source,
		EntityType: "SERVICE", EntityID: investigation.Service.ID,
		TemplateID: templateID, TemplateVersion: templateVersion,
		ObservedStart: start, ObservedEnd: end, CollectedAt: processor.now().UTC(), ReasonCode: reason,
	}, processor.filter)
	if err != nil {
		return err
	}
	if _, _, err := processor.repository.PersistEvidence(ctx, record); err != nil {
		return err
	}
	return nil
}

func (processor *CollectionProcessor) retry(ctx context.Context, job store.InvestigationCollectionJob, code string) error {
	delay := processor.retryDelay(job.AttemptCount)
	if delay < 0 || delay > time.Hour {
		delay = time.Hour
	}
	if _, err := processor.repository.RetryInvestigationCollectionJob(ctx, job.ID, job.LeaseToken, code, delay); err != nil {
		return errCollectionRetryFailed
	}
	return fmt.Errorf("%w: %s", errCollectionRetryScheduled, code)
}

type collectionFailure struct {
	code string
}

func (failure *collectionFailure) Error() string { return failure.code }

func collectionWindow(alert *store.ContextAlert, now time.Time) (time.Time, time.Time, bool) {
	if alert == nil || alert.StartsAt.IsZero() || now.IsZero() || alert.StartsAt.After(now) {
		return time.Time{}, time.Time{}, false
	}
	end := now.UTC()
	if alert.EndsAt != nil {
		postAlertEnd := alert.EndsAt.UTC().Add(collectionLookahead)
		if postAlertEnd.Before(end) {
			end = postAlertEnd
		}
	}
	start := alert.StartsAt.UTC().Add(-collectionLookback)
	if end.Sub(start) > datasource.MaxQueryWindow {
		start = end.Add(-datasource.MaxQueryWindow)
	}
	return start, end, end.After(start)
}

func parseSecretReference(raw string) (*secrets.Reference, error) {
	if raw == "" {
		return nil, nil
	}
	reference, err := secrets.ParseReference(raw)
	if err != nil {
		return nil, err
	}
	return &reference, nil
}

func templateIDs(templates []datasource.Template) []string {
	ids := make([]string, 0, len(templates))
	for _, template := range templates {
		ids = append(ids, template.ID)
	}
	return ids
}

func collectionErrorCode(err error) string {
	var queryError *prometheusconnector.QueryError
	if errors.As(err, &queryError) {
		return "prometheus_" + string(queryError.Category)
	}
	return "prometheus_unknown"
}

func collectionReasonCode(err error) evidence.CollectionFailureCode {
	switch {
	case prometheusconnector.IsErrorCategory(err, prometheusconnector.ErrorTimeout):
		return evidence.CollectionFailureTimeout
	case prometheusconnector.IsErrorCategory(err, prometheusconnector.ErrorRateLimited):
		return evidence.CollectionFailureRateLimited
	case prometheusconnector.IsErrorCategory(err, prometheusconnector.ErrorUnauthorized),
		prometheusconnector.IsErrorCategory(err, prometheusconnector.ErrorSecretUnavailable):
		return evidence.CollectionFailurePermissionDenied
	case prometheusconnector.IsErrorCategory(err, prometheusconnector.ErrorInvalidResponse),
		prometheusconnector.IsErrorCategory(err, prometheusconnector.ErrorResponseTooLarge):
		return evidence.CollectionFailureInvalidResponse
	case prometheusconnector.IsErrorCategory(err, prometheusconnector.ErrorInvalidQuery),
		prometheusconnector.IsErrorCategory(err, prometheusconnector.ErrorPolicyRejected):
		return evidence.CollectionFailureRequestRejected
	case prometheusconnector.IsErrorCategory(err, prometheusconnector.ErrorNetwork),
		prometheusconnector.IsErrorCategory(err, prometheusconnector.ErrorRemoteUnavailable):
		return evidence.CollectionFailureUnavailable
	default:
		return evidence.CollectionFailureUnknown
	}
}

// Run polls a single leased job at a time so queued work does not consume a
// lease while waiting behind a batch. Query failures are durably rescheduled
// with stable codes by Process; only infrastructure failures during claiming
// are retried by the next poll.
func (processor *CollectionProcessor) Run(ctx context.Context, pollInterval time.Duration) error {
	if processor == nil || ctx == nil || pollInterval <= 0 {
		return errors.New("collection processor, context, and positive poll interval are required")
	}
	for {
		jobs, err := processor.repository.ClaimInvestigationCollectionJobs(ctx, 1, collectionLease)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Error("worker could not claim collection task")
			if !waitContext(ctx, pollInterval) {
				return nil
			}
			continue
		}
		if len(jobs) > 0 {
			job := jobs[0]
			if err := processor.Process(ctx, job); err != nil {
				slog.Warn("worker collection task did not complete", "job_id", job.ID, "reason", err.Error())
			}
			continue
		}
		if !waitContext(ctx, pollInterval) {
			return nil
		}
	}
}

func waitContext(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
