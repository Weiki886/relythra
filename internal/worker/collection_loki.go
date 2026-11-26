package worker

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Weiki886/relythra/internal/connector/loki"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/security/secrets"
	"github.com/Weiki886/relythra/internal/store"
)

const collectionLokiResultBudget = 32 * 1024

func (processor *CollectionProcessor) collectLoki(
	ctx context.Context,
	job store.InvestigationCollectionJob,
	investigation store.InvestigationContext,
	mapping store.DataSourceMapping,
	start, end time.Time,
) error {
	if len(mapping.Templates) == 0 {
		return &collectionFailure{code: "loki_template_missing"}
	}
	templates, issues := datasource.ResolveTemplates(datasource.SourceLoki, templateIDs(mapping.Templates))
	if len(issues) > 0 || len(templates) != len(mapping.Templates) {
		return &collectionFailure{code: "loki_template_invalid"}
	}
	secretReference, err := parseSecretReference(mapping.SecretRef)
	if err != nil {
		return &collectionFailure{code: "loki_secret_reference_invalid"}
	}
	windowClipped := end.Sub(start) > datasource.MaxLokiQueryWindow
	if windowClipped {
		start = end.Add(-datasource.MaxLokiQueryWindow)
	}
	retryCode := ""
	for index, template := range templates {
		if template.Version != mapping.Templates[index].Version {
			if err := processor.persistGap(ctx, job, investigation, string(datasource.SourceLoki), template.ID, template.Version, evidence.CollectionFailureRequestRejected, start, end); err != nil {
				return &collectionFailure{code: "gap_persist_failed"}
			}
			continue
		}
		query, issues := datasource.ValidateQuery(template, datasource.QueryParameters{
			Service: investigation.Service.Slug, Environment: *investigation.Environment,
			Start: start.Format(time.RFC3339Nano), End: end.Format(time.RFC3339Nano),
			Direction: "backward", Limit: datasource.DefaultQueryLimit,
		})
		if len(issues) > 0 {
			return &collectionFailure{code: "loki_query_invalid"}
		}
		var resolvedSecret *secrets.Secret
		queryFilter := processor.filter
		var queryErr error
		if secretReference != nil {
			secret, err := processor.resolver.Resolve(ctx, *secretReference)
			if err != nil {
				queryErr = &loki.QueryError{Category: loki.ErrorSecretUnavailable}
			} else {
				resolvedSecret = &secret
				queryFilter, err = processor.filter.WithAdditionalSecrets(secret.Reveal())
				if err != nil {
					return &collectionFailure{code: "evidence_persist_failed"}
				}
			}
		}
		var result loki.Result
		if queryErr == nil {
			result, queryErr = processor.lokiConnector.Query(ctx, loki.Target{
				Endpoint: mapping.PublicSettings.Endpoint, SecretReference: secretReference, ResolvedSecret: resolvedSecret,
			}, query)
		}
		if queryErr == nil && (result.TemplateID != query.TemplateID || result.TemplateVersion != query.Version ||
			!result.Start.Equal(query.Start) || !result.End.Equal(query.End) || result.Direction != query.Direction ||
			result.Limit != query.Limit || len(result.Entries) > query.Limit) {
			queryErr = &loki.QueryError{Category: loki.ErrorInvalidResponse}
		}
		if queryErr != nil {
			code, reason := lokiCollectionFailure(queryErr)
			if err := processor.persistGap(ctx, job, investigation, string(datasource.SourceLoki), template.ID, template.Version, reason, start, end); err != nil {
				return &collectionFailure{code: "gap_persist_failed"}
			}
			if retryCode == "" {
				retryCode = code
			}
			continue
		}
		if windowClipped {
			result.Partial = true
			result.Warnings = append(result.Warnings, "Worker limited the alert window to the latest two hours.")
		}
		result, err = boundLokiCollectionResult(ctx, result, queryFilter)
		if err != nil {
			return &collectionFailure{code: "evidence_persist_failed"}
		}
		if _, _, err := processor.repository.PersistLokiEvidence(ctx, result, evidence.LokiEvidenceContext{
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

// Size the redacted JSON, including escaping, before the Evidence normalizer.
// A prefix is retained without fetching another page. Even a single oversized
// entry produces an explicitly partial snapshot instead of an endless retry.
func boundLokiCollectionResult(ctx context.Context, result loki.Result, filter *redact.Filter) (loki.Result, error) {
	clipped := false
	for {
		raw, err := json.Marshal(result)
		if err != nil {
			return loki.Result{}, err
		}
		clean, err := filter.JSON(ctx, result)
		if err != nil {
			return loki.Result{}, err
		}
		encoded, err := json.Marshal(clean)
		if err != nil {
			return loki.Result{}, err
		}
		if len(raw) <= collectionLokiResultBudget && len(encoded) <= collectionLokiResultBudget {
			return result, nil
		}
		if len(result.Entries) == 0 {
			return loki.Result{}, evidence.ErrInvalidInput
		}
		result.Entries = result.Entries[:len(result.Entries)/2]
		result.Partial = true
		if !clipped {
			result.Warnings = append(result.Warnings, "Worker clipped logs to the Evidence payload budget.")
			clipped = true
		}
	}
}

func lokiCollectionFailure(err error) (string, evidence.CollectionFailureCode) {
	var queryError *loki.QueryError
	if !errors.As(err, &queryError) {
		return "loki_unknown", evidence.CollectionFailureUnknown
	}
	reason := evidence.CollectionFailureUnknown
	switch queryError.Category {
	case loki.ErrorTimeout:
		reason = evidence.CollectionFailureTimeout
	case loki.ErrorRateLimited:
		reason = evidence.CollectionFailureRateLimited
	case loki.ErrorUnauthorized, loki.ErrorSecretUnavailable:
		reason = evidence.CollectionFailurePermissionDenied
	case loki.ErrorPolicyRejected, loki.ErrorInvalidQuery:
		reason = evidence.CollectionFailureRequestRejected
	case loki.ErrorInvalidResponse, loki.ErrorResponseTooLarge:
		reason = evidence.CollectionFailureInvalidResponse
	case loki.ErrorNetwork, loki.ErrorRemoteUnavailable:
		reason = evidence.CollectionFailureUnavailable
	}
	return "loki_" + string(queryError.Category), reason
}
