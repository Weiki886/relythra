package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	githubconnector "github.com/Weiki886/relythra/internal/connector/github"
	lokiconnector "github.com/Weiki886/relythra/internal/connector/loki"
	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	runtimeconnector "github.com/Weiki886/relythra/internal/connector/runtime"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/security/secrets"
	"github.com/Weiki886/relythra/internal/store"
)

const (
	collectionLease                 = 10 * time.Minute
	collectionRetryBase             = 5 * time.Second
	collectionLookback              = 5 * time.Minute
	collectionLookahead             = 5 * time.Minute
	collectionQueryStep             = 2 * time.Minute
	collectionMaxSeries             = 2
	collectionMaxPoints             = int(datasource.MaxQueryWindow/collectionQueryStep) + 1
	collectionRuntimeLines          = 20
	collectionRuntimeBytes          = 32 * 1024
	collectionGitHubCandidates      = 4 // Four candidates × eleven 10s-bounded requests stays below the 10m lease.
	collectionGitHubMaxFiles        = 4
	collectionGitHubDiffBytes       = 8 << 10
	collectionGitHubPatchBytes      = 2 << 10
	collectionGitHubDependencyBytes = 4 << 10
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
	PersistLokiEvidence(context.Context, lokiconnector.Result, evidence.LokiEvidenceContext, *redact.Filter) (store.Evidence, bool, error)
	PersistRuntimeEvidence(context.Context, runtimeconnector.Result, store.RuntimeEvidencePersistenceContext, *redact.Filter) ([]store.Evidence, []bool, error)
	ListInvestigationDeploymentCandidates(context.Context, string) ([]store.DeploymentEvent, error)
	PersistGitHubEvidence(context.Context, githubconnector.Result, evidence.GitHubEvidenceContext, *redact.Filter) (store.Evidence, bool, error)
	PersistEvidence(context.Context, evidence.Record) (store.Evidence, bool, error)
	CompleteInvestigationCollectionJob(context.Context, string, string) (bool, error)
	RetryInvestigationCollectionJob(context.Context, string, string, string, time.Duration) (bool, error)
}

type prometheusQueryer interface {
	Query(context.Context, prometheusconnector.Target, datasource.NormalizedQuery) (prometheusconnector.Result, error)
}

type lokiQueryer interface {
	Query(context.Context, lokiconnector.Target, datasource.NormalizedQuery) (lokiconnector.Result, error)
}

type runtimeQueryer interface {
	Query(context.Context, runtimeconnector.Target, runtimeconnector.Request) (runtimeconnector.Result, error)
}

type githubQueryer interface {
	Query(context.Context, githubconnector.Target, githubconnector.Query) (githubconnector.Result, error)
}

type CollectionOptions struct {
	LokiConnector    lokiQueryer
	RuntimeConnector runtimeQueryer
	GitHubConnector  githubQueryer
	Now              func() time.Time
	RetryDelay       func(attempt int) time.Duration
}

type CollectionProcessor struct {
	repository       collectionRepository
	connector        prometheusQueryer
	lokiConnector    lokiQueryer
	runtimeConnector runtimeQueryer
	githubConnector  githubQueryer
	resolver         prometheusconnector.SecretResolver
	filter           *redact.Filter
	now              func() time.Time
	retryDelay       func(int) time.Duration
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
		repository:       repository,
		connector:        connector,
		lokiConnector:    options.LokiConnector,
		runtimeConnector: options.RuntimeConnector,
		githubConnector:  options.GitHubConnector,
		resolver:         resolver,
		filter:           filter,
		now:              options.Now,
		retryDelay:       options.RetryDelay,
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
	retryAfter := time.Duration(0)
	for _, mapping := range mappings {
		var collectErr error
		switch mapping.SourceType {
		case datasource.SourcePrometheus:
			prometheusMappings++
			collectErr = processor.collectPrometheus(ctx, job, investigation, mapping, windowStart, windowEnd)
		case datasource.SourceLoki:
			if processor.lokiConnector != nil {
				collectErr = processor.collectLoki(ctx, job, investigation, mapping, windowStart, windowEnd)
			} else if err := processor.persistUnsupportedGaps(ctx, job, investigation, mapping, windowStart, windowEnd); err != nil {
				return processor.retry(ctx, job, "gap_persist_failed")
			}
		case datasource.SourceRuntime:
			if processor.runtimeConnector == nil {
				if err := processor.persistUnsupportedGaps(ctx, job, investigation, mapping, windowStart, windowEnd); err != nil {
					return processor.retry(ctx, job, "gap_persist_failed")
				}
			} else {
				collectErr = processor.collectRuntime(ctx, job, investigation, mapping, mappings, windowStart, windowEnd)
			}
		case datasource.SourceGitHub:
			if processor.githubConnector == nil {
				if err := processor.persistUnsupportedGaps(ctx, job, investigation, mapping, windowStart, windowEnd); err != nil {
					return processor.retry(ctx, job, "gap_persist_failed")
				}
			} else {
				collectErr = processor.collectGitHub(ctx, job, investigation, mapping, windowStart, windowEnd)
			}
		case datasource.SourceGrafana:
			// Grafana mappings describe alert metadata; alert context is already persisted.
		default:
			return processor.retry(ctx, job, "mapping_source_unsupported")
		}
		if collectErr != nil {
			var failure *collectionFailure
			if !errors.As(collectErr, &failure) {
				return processor.retry(ctx, job, "evidence_persist_failed")
			}
			if failure.code == "evidence_persist_failed" || failure.code == "gap_persist_failed" {
				return processor.retry(ctx, job, failure.code)
			}
			if retryCode == "" {
				retryCode = failure.code
			}
			retryAfter = max(retryAfter, failure.retryAfter)
		}
	}
	if prometheusMappings == 0 {
		if err := processor.persistMissingPrometheusGap(ctx, job, investigation, windowStart, windowEnd); err != nil {
			return processor.retry(ctx, job, "gap_persist_failed")
		}
	}
	if retryCode != "" {
		return processor.retryAfter(ctx, job, retryCode, retryAfter)
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

var runtimeBundleTemplates = []string{"runtime.containers.v1", "runtime.host.v1", "runtime.events.v1"}

func (processor *CollectionProcessor) collectRuntime(
	ctx context.Context,
	job store.InvestigationCollectionJob,
	investigation store.InvestigationContext,
	mapping store.DataSourceMapping,
	mappings []store.DataSourceMapping,
	start, end time.Time,
) error {
	if mapping.RuntimeType != datasource.RuntimeDockerCompose {
		return processor.persistRuntimeGaps(ctx, job, investigation, mapping, start, end, evidence.CollectionFailureUnsupported)
	}
	if !hasTemplateBundle(mapping.Templates, datasource.SourceRuntime, runtimeBundleTemplates) ||
		mapping.PublicSettings.RuntimeLabels["project"] != investigation.Project.Slug ||
		mapping.PublicSettings.RuntimeLabels["service"] != investigation.Service.Slug ||
		mapping.PublicSettings.RuntimeLabels["env"] != *investigation.Environment {
		return processor.persistRuntimeGaps(ctx, job, investigation, mapping, start, end, evidence.CollectionFailureRequestRejected)
	}
	prometheusMapping, prometheusCount := findMapping(mappings, datasource.SourcePrometheus)
	lokiMapping, lokiCount := findMapping(mappings, datasource.SourceLoki)
	if prometheusCount > 1 || lokiCount > 1 {
		return processor.persistRuntimeGaps(ctx, job, investigation, mapping, start, end, evidence.CollectionFailureRequestRejected)
	}
	if prometheusCount == 0 || lokiCount == 0 {
		return processor.persistRuntimeGaps(ctx, job, investigation, mapping, start, end, evidence.CollectionFailureMissingMapping)
	}
	prometheusSecretReference, err := parseSecretReference(prometheusMapping.SecretRef)
	if err != nil {
		return processor.persistRuntimeGaps(ctx, job, investigation, mapping, start, end, evidence.CollectionFailureRequestRejected)
	}
	lokiSecretReference, err := parseSecretReference(lokiMapping.SecretRef)
	if err != nil {
		return processor.persistRuntimeGaps(ctx, job, investigation, mapping, start, end, evidence.CollectionFailureRequestRejected)
	}
	prometheusSecret, err := processor.resolveCollectionSecret(ctx, prometheusSecretReference)
	if err != nil {
		if gapErr := processor.persistRuntimeGaps(ctx, job, investigation, mapping, start, end, evidence.CollectionFailurePermissionDenied); gapErr != nil {
			return gapErr
		}
		return &collectionFailure{code: "runtime_prometheus_secret_unavailable"}
	}
	lokiSecret, err := processor.resolveCollectionSecret(ctx, lokiSecretReference)
	if err != nil {
		if gapErr := processor.persistRuntimeGaps(ctx, job, investigation, mapping, start, end, evidence.CollectionFailurePermissionDenied); gapErr != nil {
			return gapErr
		}
		return &collectionFailure{code: "runtime_loki_secret_unavailable"}
	}
	filterSecrets := make([]string, 0, 2)
	if prometheusSecret != nil {
		filterSecrets = append(filterSecrets, prometheusSecret.Reveal())
	}
	if lokiSecret != nil {
		filterSecrets = append(filterSecrets, lokiSecret.Reveal())
	}
	persistenceFilter, err := processor.filter.WithAdditionalSecrets(filterSecrets...)
	if err != nil {
		return &collectionFailure{code: "evidence_persist_failed"}
	}
	runtimeStart := start
	windowClipped := end.Sub(runtimeStart) > runtimeconnector.MaxQueryWindow
	if windowClipped {
		runtimeStart = end.Add(-runtimeconnector.MaxQueryWindow)
	}
	request := runtimeconnector.Request{
		Runtime: mapping.RuntimeType, Action: "query", Service: investigation.Service.Slug, Environment: *investigation.Environment,
		HostID: mapping.PublicSettings.RuntimeLabels["host_id"], MappingVersion: mapping.Version,
		ContainerMappings: append([]datasource.RuntimeContainerMapping(nil), mapping.PublicSettings.ContainerMappings...),
		Start:             runtimeStart, End: end, Step: collectionQueryStep, MaxSeries: runtimeconnector.DefaultMaxSeries,
		MaxPoints: runtimeconnector.DefaultMaxPoints, MaxLogLines: collectionRuntimeLines,
	}
	result, err := processor.runtimeConnector.Query(ctx, runtimeconnector.Target{
		Prometheus: prometheusconnector.Target{Endpoint: prometheusMapping.PublicSettings.Endpoint, SecretReference: prometheusSecretReference, ResolvedSecret: prometheusSecret},
		Loki:       lokiconnector.Target{Endpoint: lokiMapping.PublicSettings.Endpoint, SecretReference: lokiSecretReference, ResolvedSecret: lokiSecret},
	}, request)
	if err != nil {
		if ctx.Err() != nil {
			return &collectionFailure{code: "runtime_collection_cancelled"}
		}
		return processor.persistRuntimeGaps(ctx, job, investigation, mapping, start, end, evidence.CollectionFailureUnavailable)
	}
	if result.Runtime != request.Runtime || result.Service != request.Service || result.Environment != request.Environment ||
		result.HostID != request.HostID || result.MappingVersion != request.MappingVersion ||
		!result.Start.Equal(runtimeStart.UTC()) || !result.End.Equal(end.UTC()) || result.Duration < 0 {
		return processor.persistRuntimeGaps(ctx, job, investigation, mapping, start, end, evidence.CollectionFailureInvalidResponse)
	}
	if windowClipped {
		result.Partial = true
		result.Gaps = append(result.Gaps, "runtime_window_clipped")
	}
	result, err = boundRuntimeCollectionEvents(ctx, result, persistenceFilter)
	if err != nil {
		return &collectionFailure{code: "evidence_persist_failed"}
	}
	_, _, err = processor.repository.PersistRuntimeEvidence(ctx, result, store.RuntimeEvidencePersistenceContext{
		InvestigationID: job.InvestigationID, ServiceID: investigation.Service.ID, CollectedAt: processor.now().UTC(),
	}, persistenceFilter)
	if err != nil {
		return &collectionFailure{code: "evidence_persist_failed"}
	}
	for _, failure := range result.Failures {
		if code, retryable := runtimeFailureRetryCode(failure); retryable {
			return &collectionFailure{code: code}
		}
	}
	return nil
}

func runtimeFailureRetryCode(failure runtimeconnector.CollectionFailure) (string, bool) {
	var source string
	switch failure.SourceType {
	case string(datasource.SourcePrometheus):
		source = "prometheus"
	case string(datasource.SourceLoki):
		source = "loki"
	default:
		return "", false
	}
	switch failure.ReasonCode {
	case runtimeconnector.CollectionFailureTimeout,
		runtimeconnector.CollectionFailureRateLimited,
		runtimeconnector.CollectionFailureUnavailable:
		return "runtime_" + source + "_" + string(failure.ReasonCode), true
	default:
		return "", false
	}
}

func (processor *CollectionProcessor) resolveCollectionSecret(ctx context.Context, reference *secrets.Reference) (*secrets.Secret, error) {
	if reference == nil {
		return nil, nil
	}
	secret, err := processor.resolver.Resolve(ctx, *reference)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

func boundRuntimeCollectionEvents(ctx context.Context, result runtimeconnector.Result, filter *redact.Filter) (runtimeconnector.Result, error) {
	trimmed := false
	if len(result.Events) > collectionRuntimeLines {
		result.Events = result.Events[:collectionRuntimeLines]
		trimmed = true
	}
	for len(result.Events) > 0 {
		redacted, err := filter.JSON(ctx, result.Events)
		if err != nil {
			return runtimeconnector.Result{}, err
		}
		encoded, err := json.Marshal(redacted)
		if err != nil {
			return runtimeconnector.Result{}, err
		}
		if len(encoded) <= collectionRuntimeBytes {
			break
		}
		result.Events = result.Events[:len(result.Events)-1]
		trimmed = true
	}
	if trimmed {
		result.Partial = true
		result.Gaps = append(result.Gaps, "runtime_events_truncated")
		result.Gaps = uniqueStrings(result.Gaps)
	}
	return result, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func (processor *CollectionProcessor) persistRuntimeGaps(
	ctx context.Context,
	job store.InvestigationCollectionJob,
	investigation store.InvestigationContext,
	mapping store.DataSourceMapping,
	start, end time.Time,
	reason evidence.CollectionFailureCode,
) error {
	if len(mapping.Templates) == 0 {
		return &collectionFailure{code: "runtime_template_missing"}
	}
	templates, issues := datasource.ResolveTemplates(datasource.SourceRuntime, templateIDs(mapping.Templates))
	if len(issues) > 0 || len(templates) != len(mapping.Templates) {
		return &collectionFailure{code: "runtime_template_invalid"}
	}
	for index, template := range templates {
		if template.Version != mapping.Templates[index].Version {
			if err := processor.persistGap(ctx, job, investigation, string(datasource.SourceRuntime), template.ID, template.Version, evidence.CollectionFailureRequestRejected, start, end); err != nil {
				return &collectionFailure{code: "gap_persist_failed"}
			}
			continue
		}
		if err := processor.persistGap(ctx, job, investigation, string(datasource.SourceRuntime), template.ID, template.Version, reason, start, end); err != nil {
			return &collectionFailure{code: "gap_persist_failed"}
		}
	}
	return nil
}

func findMapping(mappings []store.DataSourceMapping, source datasource.SourceType) (store.DataSourceMapping, int) {
	var selected store.DataSourceMapping
	count := 0
	for _, mapping := range mappings {
		if mapping.SourceType == source {
			selected = mapping
			count++
		}
	}
	return selected, count
}

func hasTemplateBundle(configured []datasource.Template, source datasource.SourceType, required []string) bool {
	ids := templateIDs(configured)
	resolved, issues := datasource.ResolveTemplates(source, ids)
	if len(issues) > 0 || len(resolved) != len(configured) {
		return false
	}
	versions := make(map[string]int, len(configured))
	for _, template := range configured {
		versions[template.ID] = template.Version
	}
	for _, id := range required {
		if versions[id] != 1 {
			return false
		}
	}
	return true
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

var githubBundleTemplates = []string{"github.commits.v1", "github.pull_requests.v1", "github.diff.v1"}

func (processor *CollectionProcessor) collectGitHub(
	ctx context.Context,
	job store.InvestigationCollectionJob,
	investigation store.InvestigationContext,
	mapping store.DataSourceMapping,
	start, end time.Time,
) error {
	if !hasTemplateBundle(mapping.Templates, datasource.SourceGitHub, githubBundleTemplates) {
		if err := processor.persistGitHubGaps(ctx, job, investigation, start, end, evidence.CollectionFailureRequestRejected); err != nil {
			return &collectionFailure{code: "gap_persist_failed"}
		}
		return nil
	}
	secretReference, err := parseSecretReference(mapping.SecretRef)
	if err != nil {
		if gapErr := processor.persistGitHubGaps(ctx, job, investigation, start, end, evidence.CollectionFailureRequestRejected); gapErr != nil {
			return &collectionFailure{code: "gap_persist_failed"}
		}
		return nil
	}
	queryFilter := processor.filter
	var resolvedSecret *secrets.Secret
	if secretReference != nil {
		secret, resolveErr := processor.resolver.Resolve(ctx, *secretReference)
		if resolveErr != nil {
			if gapErr := processor.persistGitHubGaps(ctx, job, investigation, start, end, evidence.CollectionFailurePermissionDenied); gapErr != nil {
				return &collectionFailure{code: "gap_persist_failed"}
			}
			return &collectionFailure{code: "github_secret_unavailable"}
		}
		resolvedSecret = &secret
		queryFilter, err = processor.filter.WithAdditionalSecrets(secret.Reveal())
		if err != nil {
			return &collectionFailure{code: "evidence_persist_failed"}
		}
	}
	candidates, err := processor.repository.ListInvestigationDeploymentCandidates(ctx, job.InvestigationID)
	if err != nil {
		return &collectionFailure{code: "deployment_candidate_read_failed"}
	}
	if len(candidates) == 0 {
		if err := processor.persistGitHubGaps(ctx, job, investigation, start, end, evidence.CollectionFailureMissingRevision); err != nil {
			return &collectionFailure{code: "gap_persist_failed"}
		}
		return nil
	}
	retryCode := ""
	if len(candidates) > collectionGitHubCandidates {
		if err := processor.persistGitHubGaps(ctx, job, investigation, start, end, evidence.CollectionFailureResultLimit); err != nil {
			return &collectionFailure{code: "gap_persist_failed"}
		}
		candidates = candidates[:collectionGitHubCandidates]
	}
	for _, candidate := range candidates {
		if !domain.IsID(candidate.ID) || !commitSHAValid(candidate.CommitSHA) {
			if err := processor.persistGitHubGaps(ctx, job, investigation, start, end, evidence.CollectionFailureMissingRevision); err != nil {
				return &collectionFailure{code: "gap_persist_failed"}
			}
			continue
		}
		result, queryErr := processor.githubConnector.Query(ctx, githubconnector.Target{
			Endpoint: mapping.PublicSettings.Endpoint, Repository: mapping.PublicSettings.Repository, SecretReference: secretReference, ResolvedSecret: resolvedSecret,
		}, githubconnector.Query{
			Revision: githubconnector.Revision{
				CommitSHA: candidate.CommitSHA, DeploymentEventID: candidate.ID, Source: githubconnector.RevisionSourceDeploymentEvent,
			},
			MaxFiles: collectionGitHubMaxFiles, MaxDiffBytes: collectionGitHubDiffBytes,
			MaxPatchBytes: collectionGitHubPatchBytes, MaxDependencyFileBytes: collectionGitHubDependencyBytes,
		})
		if queryErr != nil {
			retry, reason, retryAfter := githubCollectionFailure(queryErr)
			if err := processor.persistGitHubGaps(ctx, job, investigation, start, end, reason); err != nil {
				return &collectionFailure{code: "gap_persist_failed"}
			}
			if retryCode == "" {
				retryCode = retry
			}
			if retryAfter > 0 {
				return &collectionFailure{code: retry, retryAfter: retryAfter}
			}
			continue
		}
		if result.DeploymentEventID != candidate.ID || !strings.EqualFold(result.CommitSHA, candidate.CommitSHA) {
			if err := processor.persistGitHubGaps(ctx, job, investigation, start, end, evidence.CollectionFailureInvalidResponse); err != nil {
				return &collectionFailure{code: "gap_persist_failed"}
			}
			if retryCode == "" {
				retryCode = "github_invalid_response"
			}
			continue
		}
		_, _, err = processor.repository.PersistGitHubEvidence(ctx, result, evidence.GitHubEvidenceContext{
			InvestigationID: job.InvestigationID, EntityType: "SERVICE", EntityID: investigation.Service.ID, CollectedAt: processor.now().UTC(),
		}, queryFilter)
		if err != nil {
			if errors.Is(err, evidence.ErrInvalidInput) {
				if gapErr := processor.persistGitHubGaps(ctx, job, investigation, start, end, evidence.CollectionFailureResultLimit); gapErr != nil {
					return &collectionFailure{code: "gap_persist_failed"}
				}
				continue
			}
			return &collectionFailure{code: "evidence_persist_failed"}
		}
	}
	if retryCode != "" {
		return &collectionFailure{code: retryCode}
	}
	return nil
}

func (processor *CollectionProcessor) persistGitHubGaps(
	ctx context.Context, job store.InvestigationCollectionJob, investigation store.InvestigationContext,
	start, end time.Time, reason evidence.CollectionFailureCode,
) error {
	for _, templateID := range githubBundleTemplates {
		if err := processor.persistGap(ctx, job, investigation, string(datasource.SourceGitHub), templateID, 1, reason, start, end); err != nil {
			return err
		}
	}
	return nil
}

func commitSHAValid(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func githubCollectionFailure(err error) (string, evidence.CollectionFailureCode, time.Duration) {
	var queryError *githubconnector.QueryError
	if !errors.As(err, &queryError) {
		return "github_unknown", evidence.CollectionFailureUnknown, 0
	}
	code := "github_" + string(queryError.Category)
	switch queryError.Category {
	case githubconnector.ErrorTimeout:
		return code, evidence.CollectionFailureTimeout, 0
	case githubconnector.ErrorRateLimited:
		delay := queryError.RetryAfter
		if queryError.RateLimitReset.After(time.Now()) {
			resetDelay := time.Until(queryError.RateLimitReset)
			if resetDelay > delay {
				delay = resetDelay
			}
		}
		return code, evidence.CollectionFailureRateLimited, delay
	case githubconnector.ErrorPermissionDenied, githubconnector.ErrorSecretUnavailable:
		return code, evidence.CollectionFailurePermissionDenied, 0
	case githubconnector.ErrorInvalidResponse, githubconnector.ErrorResponseTooLarge:
		return code, evidence.CollectionFailureInvalidResponse, 0
	case githubconnector.ErrorInvalidQuery, githubconnector.ErrorInvalidRevision, githubconnector.ErrorPolicyRejected:
		return code, evidence.CollectionFailureRequestRejected, 0
	case githubconnector.ErrorNetwork, githubconnector.ErrorRevisionUnavailable, githubconnector.ErrorRemoteUnavailable:
		return code, evidence.CollectionFailureUnavailable, 0
	default:
		return "github_unknown", evidence.CollectionFailureUnknown, 0
	}
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
	return processor.retryAfter(ctx, job, code, 0)
}

func (processor *CollectionProcessor) retryAfter(ctx context.Context, job store.InvestigationCollectionJob, code string, retryAfter time.Duration) error {
	delay := max(processor.retryDelay(job.AttemptCount), retryAfter)
	if delay < 0 || delay > 24*time.Hour {
		delay = 24 * time.Hour
	}
	if _, err := processor.repository.RetryInvestigationCollectionJob(ctx, job.ID, job.LeaseToken, code, delay); err != nil {
		return errCollectionRetryFailed
	}
	return fmt.Errorf("%w: %s", errCollectionRetryScheduled, code)
}

type collectionFailure struct {
	code       string
	retryAfter time.Duration
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
