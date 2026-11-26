package worker_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/security/secrets"
	"github.com/Weiki886/relythra/internal/store"
	"github.com/Weiki886/relythra/internal/worker"
)

const (
	collectionInvestigationID = "10000000-0000-4000-8000-000000000001"
	collectionServiceID       = "20000000-0000-4000-8000-000000000001"
	collectionJobID           = "30000000-0000-4000-8000-000000000001"
	collectionLeaseToken      = "40000000-0000-4000-8000-000000000001"
	collectionProjectID       = "50000000-0000-4000-8000-000000000001"
	collectionMappingID       = "60000000-0000-4000-8000-000000000001"
)

type collectionRepositoryFake struct {
	context             store.InvestigationContext
	mappings            []store.DataSourceMapping
	persistedPrometheus []evidence.Record
	persistedGaps       []evidence.Record
	completeCalls       int
	retryCalls          int
	retryCode           string
	persistErr          error
	completedBeforeSave bool
}

func (repository *collectionRepositoryFake) ClaimInvestigationCollectionJobs(context.Context, int, time.Duration) ([]store.InvestigationCollectionJob, error) {
	return nil, nil
}

func (repository *collectionRepositoryFake) GetInvestigationContext(context.Context, string) (store.InvestigationContext, error) {
	return repository.context, nil
}

func (repository *collectionRepositoryFake) ListDataSourceMappings(context.Context, string, string, string) ([]store.DataSourceMapping, error) {
	return repository.mappings, nil
}

func (repository *collectionRepositoryFake) PersistPrometheusEvidence(_ context.Context, result prometheusconnector.Result, metadata evidence.PrometheusEvidenceContext, filter *redact.Filter) (store.Evidence, bool, error) {
	if repository.persistErr != nil {
		return store.Evidence{}, false, repository.persistErr
	}
	record, err := evidence.FromPrometheusResult(context.Background(), result, metadata, filter)
	if err != nil {
		return store.Evidence{}, false, err
	}
	repository.persistedPrometheus = append(repository.persistedPrometheus, record)
	return store.Evidence{ID: "evidence"}, true, nil
}

func (repository *collectionRepositoryFake) PersistEvidence(_ context.Context, record evidence.Record) (store.Evidence, bool, error) {
	if repository.persistErr != nil {
		return store.Evidence{}, false, repository.persistErr
	}
	repository.persistedGaps = append(repository.persistedGaps, record)
	return store.Evidence{ID: "gap"}, true, nil
}

func (repository *collectionRepositoryFake) CompleteInvestigationCollectionJob(context.Context, string, string) (bool, error) {
	repository.completeCalls++
	repository.completedBeforeSave = len(repository.persistedPrometheus)+len(repository.persistedGaps) == 0
	return true, nil
}

func (repository *collectionRepositoryFake) RetryInvestigationCollectionJob(_ context.Context, _, _ string, code string, _ time.Duration) (bool, error) {
	repository.retryCalls++
	repository.retryCode = code
	return false, nil
}

type collectionSecretResolverFake struct{}

func (collectionSecretResolverFake) Resolve(context.Context, secrets.Reference) (secrets.Secret, error) {
	return secrets.Secret{}, errors.New("unexpected secret resolution")
}

type collectionPrometheusFake struct {
	result prometheusconnector.Result
	err    error
	calls  []struct {
		target prometheusconnector.Target
		query  datasource.NormalizedQuery
	}
}

func (connector *collectionPrometheusFake) Query(_ context.Context, target prometheusconnector.Target, query datasource.NormalizedQuery) (prometheusconnector.Result, error) {
	connector.calls = append(connector.calls, struct {
		target prometheusconnector.Target
		query  datasource.NormalizedQuery
	}{target: target, query: query})
	return connector.result, connector.err
}

func TestCollectionWorkerPersistsPrometheusEvidenceBeforeCompletingLease(t *testing.T) {
	ctx, mapping := validCollectionContextAndMapping()
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{mapping}}
	connector := &collectionPrometheusFake{result: validCollectionPrometheusResult()}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, connector, collectionSecretResolverFake{}, filter, collectionOptions())
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}

	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(connector.calls) != 1 || len(repository.persistedPrometheus) != 1 {
		t.Fatalf("query calls=%d persisted Prometheus=%d, want 1 each", len(connector.calls), len(repository.persistedPrometheus))
	}
	if repository.completeCalls != 1 || repository.completedBeforeSave {
		t.Fatalf("completion calls=%d before save=%v, want completion after persistence", repository.completeCalls, repository.completedBeforeSave)
	}
	query := connector.calls[0].query
	if query.TemplateID != "prometheus.service.latency.v1" || query.QueryType != datasource.QueryTypeRange ||
		query.Service != ctx.Service.Slug || query.Environment != *ctx.Environment || query.End.Sub(query.Start) > datasource.MaxQueryWindow {
		t.Fatalf("query was not fixed and bounded: %+v", query)
	}
}

func TestCollectionWorkerRedactsResolvedDatasourceSecretFromEvidence(t *testing.T) {
	const canary = "worker-prometheus-credential-canary"
	t.Setenv("RELYTHRA_TEST_PROMETHEUS_TOKEN", canary)
	ctx, mapping := validCollectionContextAndMapping()
	mapping.SecretRef = "env:RELYTHRA_TEST_PROMETHEUS_TOKEN"
	result := validCollectionPrometheusResult()
	result.Series[0].Labels["credential_echo"] = canary
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{mapping}}
	connector := &collectionPrometheusFake{result: result}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, connector, secrets.NewResolver(nil, nil), filter, collectionOptions())
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(connector.calls) != 1 || connector.calls[0].target.ResolvedSecret == nil || connector.calls[0].target.ResolvedSecret.Reveal() != canary {
		t.Fatal("resolved credential was not scoped to the Prometheus request")
	}
	if len(repository.persistedPrometheus) != 1 || strings.Contains(string(repository.persistedPrometheus[0].ValueSummary), canary) {
		t.Fatalf("Evidence summary did not redact datasource credential: %s", repository.persistedPrometheus[0].ValueSummary)
	}
}

func TestCollectionWorkerDoesNotCompleteWhenEvidencePersistenceFails(t *testing.T) {
	ctx, mapping := validCollectionContextAndMapping()
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{mapping}, persistErr: errors.New("database temporarily unavailable")}
	connector := &collectionPrometheusFake{result: validCollectionPrometheusResult()}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, connector, collectionSecretResolverFake{}, filter, collectionOptions())
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}

	if err := processor.Process(context.Background(), validCollectionJob()); err == nil {
		t.Fatal("Process() error = nil, want persistence failure")
	}
	if repository.completeCalls != 0 {
		t.Fatalf("completion calls=%d, want 0 when evidence persistence fails", repository.completeCalls)
	}
	if repository.retryCalls != 1 || repository.retryCode != "evidence_persist_failed" {
		t.Fatalf("retry calls=%d code=%q, want stable evidence persistence failure", repository.retryCalls, repository.retryCode)
	}
}

func TestCollectionWorkerRecordsMissingMappingWithoutSilentCompletion(t *testing.T) {
	ctx, _ := validCollectionContextAndMapping()
	repository := &collectionRepositoryFake{context: ctx}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{}, collectionSecretResolverFake{}, filter, collectionOptions())
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}

	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(repository.persistedGaps) != 1 || repository.completeCalls != 1 {
		t.Fatalf("gap records=%d completion calls=%d, want one explicit gap then completion", len(repository.persistedGaps), repository.completeCalls)
	}
	var summary map[string]any
	if err := jsonUnmarshal(repository.persistedGaps[0].ValueSummary, &summary); err != nil {
		t.Fatal(err)
	}
	if summary["kind"] != "collection_gap" || summary["reason_code"] != "missing_mapping" {
		t.Fatalf("gap summary = %#v, want missing_mapping", summary)
	}
}

func TestCollectionWorkerPersistsGapForConfiguredUnsupportedSource(t *testing.T) {
	ctx, mapping := validCollectionContextAndMapping()
	mapping.SourceType = datasource.SourceLoki
	mapping.Templates = []datasource.Template{{ID: "loki.service.errors.v1", Version: 1, Source: datasource.SourceLoki}}
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{mapping}}
	filter, _ := redact.NewFilter()
	connector := &collectionPrometheusFake{}
	processor, err := worker.NewCollectionProcessor(repository, connector, collectionSecretResolverFake{}, filter, collectionOptions())
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}

	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(connector.calls) != 0 || len(repository.persistedGaps) != 2 || repository.completeCalls != 1 {
		t.Fatalf("connector calls=%d gaps=%d completion=%d; unsupported source and missing Prometheus mapping must be explicit", len(connector.calls), len(repository.persistedGaps), repository.completeCalls)
	}
}

func validCollectionContextAndMapping() (store.InvestigationContext, store.DataSourceMapping) {
	started := time.Now().UTC().Add(-20 * time.Minute).Truncate(time.Second)
	environment := "prod"
	context := store.InvestigationContext{
		InvestigationID: collectionInvestigationID,
		Status:          domain.InvestigationMatched,
		StartedAt:       started,
		Project:         store.ContextEntity{ID: collectionProjectID, Slug: "orders"},
		Service:         &store.ContextEntity{ID: collectionServiceID, Slug: "orders-api"},
		Environment:     &environment,
		MappingStatus:   "MATCHED",
		Alert:           &store.ContextAlert{ID: "alert", Status: "FIRING", StartsAt: started.Add(-5 * time.Minute)},
	}
	mapping := store.DataSourceMapping{
		ID:          collectionMappingID,
		ProjectID:   collectionProjectID,
		ServiceID:   collectionServiceID,
		Environment: environment,
		SourceType:  datasource.SourcePrometheus,
		PublicSettings: datasource.PublicSettings{
			Endpoint: "https://prometheus.example.test",
		},
		Templates: []datasource.Template{{ID: "prometheus.service.latency.v1", Version: 1, Source: datasource.SourcePrometheus}},
		Version:   3,
	}
	return context, mapping
}

func validCollectionJob() store.InvestigationCollectionJob {
	return store.InvestigationCollectionJob{ID: collectionJobID, InvestigationID: collectionInvestigationID, AttemptCount: 1, LeaseToken: collectionLeaseToken}
}

func validCollectionPrometheusResult() prometheusconnector.Result {
	collected := time.Now().UTC()
	return prometheusconnector.Result{
		TemplateID: "prometheus.service.latency.v1", TemplateVersion: 1, QueryType: datasource.QueryTypeRange,
		Query: "fixed-query", Unit: "seconds", Start: collected.Add(-5 * time.Minute), End: collected,
		Step: 30 * time.Second, Duration: time.Second, SourceReference: "https://prometheus.example.test/api/v1/query_range",
		ResponseSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Series:         []prometheusconnector.Series{{Labels: map[string]string{"route": "/checkout"}, Samples: []prometheusconnector.Sample{{Timestamp: collected.Add(-time.Minute), Value: 0.25}}}},
		LatestSampleAt: &collected,
	}
}

func collectionOptions() worker.CollectionOptions {
	return worker.CollectionOptions{Now: time.Now, RetryDelay: func(int) time.Duration { return time.Second }}
}

func jsonUnmarshal(raw []byte, target any) error {
	return json.Unmarshal(raw, target)
}
