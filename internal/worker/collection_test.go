package worker_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
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
	context                store.InvestigationContext
	mappings               []store.DataSourceMapping
	persistedPrometheus    []evidence.Record
	persistedLoki          []evidence.Record
	persistedGaps          []evidence.Record
	persistedRuntime       []evidence.Record
	persistedGitHub        []githubconnector.Result
	persistedGitHubRecords []evidence.Record
	deploymentCandidates   []store.DeploymentEvent
	completeCalls          int
	retryCalls             int
	retryCode              string
	retryDelay             time.Duration
	persistErr             error
	runtimePersistErr      error
	completedBeforeSave    bool
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

func (repository *collectionRepositoryFake) ListInvestigationDeploymentCandidates(context.Context, string) ([]store.DeploymentEvent, error) {
	return repository.deploymentCandidates, nil
}

func (repository *collectionRepositoryFake) PersistGitHubEvidence(_ context.Context, result githubconnector.Result, metadata evidence.GitHubEvidenceContext, filter *redact.Filter) (store.Evidence, bool, error) {
	if repository.persistErr != nil {
		return store.Evidence{}, false, repository.persistErr
	}
	record, err := evidence.FromGitHubResult(context.Background(), result, metadata, filter)
	if err != nil {
		return store.Evidence{}, false, err
	}
	repository.persistedGitHub = append(repository.persistedGitHub, result)
	repository.persistedGitHubRecords = append(repository.persistedGitHubRecords, record)
	return store.Evidence{ID: "github-evidence"}, true, nil
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

func (repository *collectionRepositoryFake) PersistLokiEvidence(ctx context.Context, result lokiconnector.Result, metadata evidence.LokiEvidenceContext, filter *redact.Filter) (store.Evidence, bool, error) {
	if repository.persistErr != nil {
		return store.Evidence{}, false, repository.persistErr
	}
	record, err := evidence.FromLokiResult(ctx, result, metadata, filter)
	if err != nil {
		return store.Evidence{}, false, err
	}
	repository.persistedLoki = append(repository.persistedLoki, record)
	return store.Evidence{ID: "loki-evidence"}, true, nil
}

func (repository *collectionRepositoryFake) PersistEvidence(_ context.Context, record evidence.Record) (store.Evidence, bool, error) {
	if repository.persistErr != nil {
		return store.Evidence{}, false, repository.persistErr
	}
	repository.persistedGaps = append(repository.persistedGaps, record)
	return store.Evidence{ID: "gap"}, true, nil
}

func (repository *collectionRepositoryFake) PersistRuntimeEvidence(ctx context.Context, result runtimeconnector.Result, metadata store.RuntimeEvidencePersistenceContext, filter *redact.Filter) ([]store.Evidence, []bool, error) {
	if repository.runtimePersistErr != nil {
		return nil, nil, repository.runtimePersistErr
	}
	records, err := evidence.FromRuntimeResult(ctx, result, evidence.RuntimeEvidenceContext{
		InvestigationID: metadata.InvestigationID, ToolCallID: metadata.ToolCallID, CollectedAt: metadata.CollectedAt,
	}, filter)
	if err != nil {
		return nil, nil, err
	}
	repository.persistedRuntime = append(repository.persistedRuntime, records...)
	items := make([]store.Evidence, len(records))
	created := make([]bool, len(records))
	for index := range records {
		items[index] = store.Evidence{ID: "runtime-evidence"}
		created[index] = true
	}
	return items, created, nil
}

func (repository *collectionRepositoryFake) CompleteInvestigationCollectionJob(context.Context, string, string) (bool, error) {
	repository.completeCalls++
	repository.completedBeforeSave = len(repository.persistedPrometheus)+len(repository.persistedLoki)+len(repository.persistedGaps)+len(repository.persistedRuntime)+len(repository.persistedGitHub) == 0
	return true, nil
}

func (repository *collectionRepositoryFake) RetryInvestigationCollectionJob(_ context.Context, _, _ string, code string, delay time.Duration) (bool, error) {
	repository.retryCalls++
	repository.retryCode = code
	repository.retryDelay = delay
	return false, nil
}

type collectionSecretResolverFake struct{}

func (collectionSecretResolverFake) Resolve(context.Context, secrets.Reference) (secrets.Secret, error) {
	return secrets.Secret{}, errors.New("unexpected secret resolution")
}

type collectionSecretResolverStatic struct {
	secret string
}

func (resolver collectionSecretResolverStatic) Resolve(context.Context, secrets.Reference) (secrets.Secret, error) {
	secret := resolver.secret
	if secret == "" {
		secret = "runtime-test-token"
	}
	return secrets.New(secret)
}

type collectionPrometheusFake struct {
	result         prometheusconnector.Result
	err            error
	failTemplateID string
	calls          []struct {
		target prometheusconnector.Target
		query  datasource.NormalizedQuery
	}
}

func (connector *collectionPrometheusFake) Query(_ context.Context, target prometheusconnector.Target, query datasource.NormalizedQuery) (prometheusconnector.Result, error) {
	connector.calls = append(connector.calls, struct {
		target prometheusconnector.Target
		query  datasource.NormalizedQuery
	}{target: target, query: query})
	if query.TemplateID == connector.failTemplateID {
		return prometheusconnector.Result{}, &prometheusconnector.QueryError{Category: prometheusconnector.ErrorTimeout}
	}
	if connector.err != nil {
		return prometheusconnector.Result{}, connector.err
	}
	result := connector.result
	result.TemplateID = query.TemplateID
	result.TemplateVersion = query.Version
	result.QueryType = query.QueryType
	result.Start = query.Start
	result.End = query.End
	result.Step = query.Step
	if len(result.Series) > query.MaxSeries {
		result.Series = result.Series[:query.MaxSeries]
		result.Partial = true
	}
	for index := range result.Series {
		if len(result.Series[index].Samples) > query.MaxPoints {
			result.Series[index].Samples = result.Series[index].Samples[:query.MaxPoints]
			result.Partial = true
		}
	}
	return result, nil
}

func TestCollectionWorkerKeepsSixHourPrometheusEvidenceWithinPayloadLimit(t *testing.T) {
	ctx, mapping := validCollectionContextAndMapping()
	collected := time.Date(2026, 11, 26, 6, 0, 0, 0, time.UTC)
	ctx.Alert.StartsAt = collected.Add(-6 * time.Hour)
	ctx.Alert.Status = "FIRING"
	result := validCollectionPrometheusResult()
	result.Series = make([]prometheusconnector.Series, 2)
	for seriesIndex := range result.Series {
		series := prometheusconnector.Series{Labels: map[string]string{"route": "/checkout", "series": string(rune('a' + seriesIndex))}}
		for sampleIndex := 0; sampleIndex < 721; sampleIndex++ {
			series.Samples = append(series.Samples, prometheusconnector.Sample{
				Timestamp: collected.Add(-6*time.Hour + time.Duration(sampleIndex)*30*time.Second),
				Value:     0.25,
			})
		}
		result.Series[seriesIndex] = series
	}
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{mapping}}
	connector := &collectionPrometheusFake{result: result}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, connector, collectionSecretResolverFake{}, filter, worker.CollectionOptions{
		Now: func() time.Time { return collected },
	})
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(connector.calls) != 1 {
		t.Fatalf("connector calls = %d, want 1", len(connector.calls))
	}
	query := connector.calls[0].query
	if query.Step != 2*time.Minute || query.MaxSeries != 2 || query.MaxPoints != 181 {
		t.Fatalf("query budget = step %s, series %d, points %d; want 2m, 2, 181", query.Step, query.MaxSeries, query.MaxPoints)
	}
	if len(repository.persistedPrometheus) != 1 {
		t.Fatalf("persisted evidence = %d, want 1", len(repository.persistedPrometheus))
	}
	if got := len(repository.persistedPrometheus[0].ValueSummary); got > 64*1024 {
		t.Fatalf("Evidence value summary is %d bytes, exceeds 64 KiB", got)
	}
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

func TestCollectionWorkerContinuesIndependentTemplatesAndMappingsAfterQueryFailure(t *testing.T) {
	ctx, prometheusMapping := validCollectionContextAndMapping()
	prometheusMapping.Templates = append(prometheusMapping.Templates, datasource.Template{
		ID: "prometheus.service.request_rate.v1", Version: 1, Source: datasource.SourcePrometheus,
	})
	lokiMapping := store.DataSourceMapping{
		ID: "70000000-0000-4000-8000-000000000001", ProjectID: collectionProjectID,
		ServiceID: collectionServiceID, Environment: "prod", SourceType: datasource.SourceLoki,
		Templates: []datasource.Template{{ID: "loki.service.errors.v1", Version: 1, Source: datasource.SourceLoki}},
	}
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{prometheusMapping, lokiMapping}}
	connector := &collectionPrometheusFake{result: validCollectionPrometheusResult(), failTemplateID: "prometheus.service.latency.v1"}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, connector, collectionSecretResolverFake{}, filter, collectionOptions())
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}

	if err := processor.Process(context.Background(), validCollectionJob()); err == nil {
		t.Fatal("Process() error = nil, want retry after one source timeout")
	}
	if len(connector.calls) != 2 || connector.calls[1].query.TemplateID != "prometheus.service.request_rate.v1" {
		t.Fatalf("Prometheus calls=%+v, want both templates despite first timeout", connector.calls)
	}
	if len(repository.persistedPrometheus) != 1 || len(repository.persistedGaps) != 2 {
		t.Fatalf("persisted Prometheus=%d gaps=%d, want healthy metric plus timeout and Loki gaps", len(repository.persistedPrometheus), len(repository.persistedGaps))
	}
	if repository.completeCalls != 0 || repository.retryCalls != 1 || repository.retryCode != "prometheus_timeout" {
		t.Fatalf("completion=%d retry=%d code=%q, want one retry and no completion", repository.completeCalls, repository.retryCalls, repository.retryCode)
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

func TestCollectionWorkerPersistsConfiguredRuntimeEvidenceBeforeCompletingLease(t *testing.T) {
	invContext, latencyMapping := validCollectionContextAndMapping()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	invContext.Alert.StartsAt = now.Add(-3 * time.Minute)
	latencyMapping.PublicSettings.Endpoint = "https://prometheus.example.test"
	latencyMapping.SecretRef = "env:PROMETHEUS_TOKEN"
	lokiMapping, runtimeMapping := validWorkerRuntimeMappings()
	lokiMapping.SecretRef = "env:LOKI_TOKEN"
	repository := &collectionRepositoryFake{context: invContext, mappings: []store.DataSourceMapping{latencyMapping, lokiMapping, runtimeMapping}}
	prometheus := &collectionPrometheusFake{result: validCollectionPrometheusResult()}
	loki := &collectionLokiFake{result: validCollectionLokiResult(t)}
	runtime := &collectionRuntimeFake{result: runtimeconnector.Result{
		Runtime: datasource.RuntimeDockerCompose, Service: "orders-api", Environment: "prod", HostID: "demo-host", MappingVersion: runtimeMapping.Version,
		Hosts:      []runtimeconnector.Host{{HostID: "demo-host", Instance: "runtime-test-token", CPU: runtimeconnector.Measurement{Empty: true}, MemoryAvailable: runtimeconnector.Measurement{Empty: true}, Load: runtimeconnector.Measurement{Empty: true}}},
		Containers: []runtimeconnector.Container{}, Events: []runtimeconnector.Event{}, Gaps: []string{}, Failures: []runtimeconnector.CollectionFailure{},
	}}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, prometheus, collectionSecretResolverStatic{}, filter, worker.CollectionOptions{
		LokiConnector: loki, RuntimeConnector: runtime, Now: func() time.Time { return now }, RetryDelay: func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(runtime.calls) != 1 || len(repository.persistedRuntime) != 8 || repository.completeCalls != 1 || repository.completedBeforeSave {
		t.Fatalf("runtime calls=%d persisted=%d complete=%d completedBeforeSave=%v", len(runtime.calls), len(repository.persistedRuntime), repository.completeCalls, repository.completedBeforeSave)
	}
	call := runtime.calls[0]
	if call.target.Prometheus.Endpoint != latencyMapping.PublicSettings.Endpoint || call.target.Loki.Endpoint != lokiMapping.PublicSettings.Endpoint ||
		call.target.Prometheus.SecretReference == nil || call.target.Prometheus.SecretReference.String() != latencyMapping.SecretRef ||
		call.target.Loki.SecretReference == nil || call.target.Loki.SecretReference.String() != lokiMapping.SecretRef {
		t.Fatalf("runtime targets = %+v", call.target)
	}
	if call.request.Runtime != datasource.RuntimeDockerCompose || call.request.Service != "orders-api" || call.request.Environment != "prod" ||
		call.request.HostID != "demo-host" || call.request.MappingVersion != runtimeMapping.Version || call.request.Step != 2*time.Minute ||
		call.request.MaxSeries != runtimeconnector.DefaultMaxSeries || call.request.MaxPoints != runtimeconnector.DefaultMaxPoints || call.request.MaxLogLines != 20 {
		t.Fatalf("runtime request = %+v", call.request)
	}
	for _, record := range repository.persistedRuntime {
		if record.InvestigationID != collectionInvestigationID || record.SourceType != evidence.SourceRuntime || record.ToolCallID != nil || !record.CollectedAt.Equal(now) {
			t.Fatalf("runtime evidence metadata = %+v", record)
		}
		if strings.Contains(string(record.ValueSummary), "runtime-test-token") {
			t.Fatalf("Runtime Evidence leaked the resolved telemetry secret: %s", record.ValueSummary)
		}
	}
	if runtime.calls[0].target.Prometheus.ResolvedSecret == nil || runtime.calls[0].target.Prometheus.ResolvedSecret.Reveal() != "runtime-test-token" ||
		runtime.calls[0].target.Loki.ResolvedSecret == nil || runtime.calls[0].target.Loki.ResolvedSecret.Reveal() != "runtime-test-token" {
		t.Fatal("Runtime query targets did not receive the resolved mapped secrets")
	}
}

func TestCollectionWorkerClipsRuntimeWindowToConnectorLimitAndMarksPartial(t *testing.T) {
	invContext, prometheusMapping := validCollectionContextAndMapping()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	invContext.Alert.StartsAt = now.Add(-4 * time.Hour)
	lokiMapping, runtimeMapping := validWorkerRuntimeMappings()
	runtime := &collectionRuntimeFake{result: runtimeconnector.Result{
		Runtime: datasource.RuntimeDockerCompose, Service: "orders-api", Environment: "prod", HostID: "demo-host", MappingVersion: runtimeMapping.Version,
		Hosts: []runtimeconnector.Host{}, Containers: []runtimeconnector.Container{}, Events: []runtimeconnector.Event{}, Gaps: []string{}, Failures: []runtimeconnector.CollectionFailure{},
	}}
	repository := &collectionRepositoryFake{context: invContext, mappings: []store.DataSourceMapping{prometheusMapping, lokiMapping, runtimeMapping}}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{
		LokiConnector: &collectionLokiFake{result: validCollectionLokiResult(t)}, RuntimeConnector: runtime, Now: func() time.Time { return now }, RetryDelay: func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(runtime.calls) != 1 || runtime.calls[0].request.End.Sub(runtime.calls[0].request.Start) != runtimeconnector.MaxQueryWindow {
		t.Fatalf("Runtime request window = %+v", runtime.calls)
	}
	var summary struct {
		Partial bool     `json:"partial"`
		Gaps    []string `json:"gaps"`
	}
	if err := jsonUnmarshal(repository.persistedRuntime[0].ValueSummary, &summary); err != nil {
		t.Fatal(err)
	}
	if !summary.Partial || !containsString(summary.Gaps, "runtime_window_clipped") {
		t.Fatalf("clipped Runtime summary is missing partial coverage: %+v", summary)
	}
}

func TestCollectionWorkerBoundsRuntimeLifecyclePayload(t *testing.T) {
	invContext, prometheusMapping := validCollectionContextAndMapping()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	invContext.Alert.StartsAt = now.Add(-3 * time.Minute)
	lokiMapping, runtimeMapping := validWorkerRuntimeMappings()
	filter, _ := redact.NewFilter()
	events := make([]runtimeconnector.Event, 25)
	for index := range events {
		events[index] = runtimeconnector.Event{
			Timestamp: now.Add(-time.Duration(index+1) * time.Second), Classification: "unverified_log_match",
			SourceReference: "https://loki.example.test/loki/api/v1/query_range",
			Line:            redact.UntrustedData{Trust: "untrusted_data", Source: "loki", Content: strings.Repeat("x", 3000), OriginalBytes: 3000},
		}
	}
	runtime := &collectionRuntimeFake{result: runtimeconnector.Result{
		Runtime: datasource.RuntimeDockerCompose, Service: "orders-api", Environment: "prod", HostID: "demo-host", MappingVersion: runtimeMapping.Version,
		Hosts: []runtimeconnector.Host{}, Containers: []runtimeconnector.Container{}, Events: events, Gaps: []string{}, Failures: []runtimeconnector.CollectionFailure{},
	}}
	repository := &collectionRepositoryFake{context: invContext, mappings: []store.DataSourceMapping{prometheusMapping, lokiMapping, runtimeMapping}}
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{
		LokiConnector: &collectionLokiFake{result: validCollectionLokiResult(t)}, RuntimeConnector: runtime, Now: func() time.Time { return now }, RetryDelay: func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(repository.persistedRuntime) != 8 {
		t.Fatalf("Runtime Evidence count=%d, want eight", len(repository.persistedRuntime))
	}
	var summary struct {
		Partial bool                     `json:"partial"`
		Gaps    []string                 `json:"gaps"`
		Events  []runtimeconnector.Event `json:"events"`
	}
	if err := jsonUnmarshal(repository.persistedRuntime[7].ValueSummary, &summary); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(summary.Events)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Partial || len(summary.Events) >= len(events) || len(encoded) > 32*1024 || !containsString(summary.Gaps, "runtime_events_truncated") {
		t.Fatalf("Runtime lifecycle payload was not bounded with a partial marker: events=%d bytes=%d summary=%+v", len(summary.Events), len(encoded), summary)
	}
}

func TestCollectionWorkerRetriesRuntimePartialResultsWithTransientFailures(t *testing.T) {
	invContext, prometheusMapping := validCollectionContextAndMapping()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	invContext.Alert.StartsAt = now.Add(-3 * time.Minute)
	lokiMapping, runtimeMapping := validWorkerRuntimeMappings()
	runtime := &collectionRuntimeFake{result: runtimeconnector.Result{
		Runtime: datasource.RuntimeDockerCompose, Service: "orders-api", Environment: "prod", HostID: "demo-host", MappingVersion: runtimeMapping.Version,
		Hosts: []runtimeconnector.Host{}, Containers: []runtimeconnector.Container{}, Events: []runtimeconnector.Event{}, Gaps: []string{},
		Failures: []runtimeconnector.CollectionFailure{
			{SourceType: "PROMETHEUS", TemplateID: "prometheus.runtime.host.memory_available.v1", TemplateVersion: 1, ReasonCode: runtimeconnector.CollectionFailurePermissionDenied},
			{SourceType: "PROMETHEUS", TemplateID: "prometheus.runtime.host.cpu.v1", TemplateVersion: 1, ReasonCode: runtimeconnector.CollectionFailureTimeout},
		},
	}}
	repository := &collectionRepositoryFake{context: invContext, mappings: []store.DataSourceMapping{prometheusMapping, lokiMapping, runtimeMapping}}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{
		LokiConnector: &collectionLokiFake{result: validCollectionLokiResult(t)}, RuntimeConnector: runtime, Now: func() time.Time { return now }, RetryDelay: func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err == nil {
		t.Fatal("Process succeeded despite a retryable Runtime source failure")
	}
	if len(repository.persistedRuntime) != 8 || repository.retryCalls != 1 || repository.retryCode != "runtime_prometheus_timeout" || repository.completeCalls != 0 {
		t.Fatalf("persisted=%d retry=%d code=%q complete=%d", len(repository.persistedRuntime), repository.retryCalls, repository.retryCode, repository.completeCalls)
	}
}

func TestCollectionWorkerDoesNotRetryUnknownRuntimeFailureCodes(t *testing.T) {
	invContext, prometheusMapping := validCollectionContextAndMapping()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	invContext.Alert.StartsAt = now.Add(-3 * time.Minute)
	lokiMapping, runtimeMapping := validWorkerRuntimeMappings()
	runtime := &collectionRuntimeFake{result: runtimeconnector.Result{
		Runtime: datasource.RuntimeDockerCompose, Service: "orders-api", Environment: "prod", HostID: "demo-host", MappingVersion: runtimeMapping.Version,
		Hosts: []runtimeconnector.Host{}, Containers: []runtimeconnector.Container{}, Events: []runtimeconnector.Event{}, Gaps: []string{},
		Failures: []runtimeconnector.CollectionFailure{{SourceType: "PROMETHEUS", TemplateID: "prometheus.runtime.host.cpu.v1", TemplateVersion: 1, ReasonCode: runtimeconnector.CollectionFailureUnknown}},
	}}
	repository := &collectionRepositoryFake{context: invContext, mappings: []store.DataSourceMapping{prometheusMapping, lokiMapping, runtimeMapping}}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{
		LokiConnector: &collectionLokiFake{result: validCollectionLokiResult(t)}, RuntimeConnector: runtime, Now: func() time.Time { return now }, RetryDelay: func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if repository.retryCalls != 0 || repository.completeCalls != 1 {
		t.Fatalf("retry=%d complete=%d", repository.retryCalls, repository.completeCalls)
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func TestCollectionWorkerPersistsRuntimeGapsWhenBackingTelemetryMappingsAreMissing(t *testing.T) {
	invContext, _ := validCollectionContextAndMapping()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	invContext.Alert.StartsAt = now.Add(-3 * time.Minute)
	_, runtimeMapping := validWorkerRuntimeMappings()
	repository := &collectionRepositoryFake{context: invContext, mappings: []store.DataSourceMapping{runtimeMapping}}
	runtime := &collectionRuntimeFake{}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{
		RuntimeConnector: runtime, Now: func() time.Time { return now }, RetryDelay: func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(runtime.calls) != 0 || len(repository.persistedRuntime) != 0 || len(repository.persistedGaps) != 4 || repository.completeCalls != 1 {
		t.Fatalf("runtime calls=%d runtime evidence=%d gaps=%d completion=%d", len(runtime.calls), len(repository.persistedRuntime), len(repository.persistedGaps), repository.completeCalls)
	}
	seenRuntimeGaps := map[string]bool{}
	for _, record := range repository.persistedGaps {
		if record.SourceType != evidence.SourceRuntime {
			continue
		}
		var summary map[string]any
		if err := jsonUnmarshal(record.ValueSummary, &summary); err != nil {
			t.Fatal(err)
		}
		if summary["reason_code"] != string(evidence.CollectionFailureMissingMapping) {
			t.Fatalf("runtime gap = %#v", summary)
		}
		var query map[string]any
		if err := jsonUnmarshal(record.QueryParameters, &query); err != nil {
			t.Fatal(err)
		}
		seenRuntimeGaps[query["template_id"].(string)] = true
	}
	if len(seenRuntimeGaps) != 3 {
		t.Fatalf("runtime gap templates = %#v", seenRuntimeGaps)
	}
}

func TestCollectionWorkerPersistsRuntimeGapsWhenBackingMappingsAreAmbiguous(t *testing.T) {
	invContext, prometheusMapping := validCollectionContextAndMapping()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	invContext.Alert.StartsAt = now.Add(-3 * time.Minute)
	lokiMapping, runtimeMapping := validWorkerRuntimeMappings()
	duplicatePrometheusMapping := prometheusMapping
	duplicatePrometheusMapping.ID = "90000000-0000-4000-8000-000000000001"
	duplicatePrometheusMapping.Version++
	repository := &collectionRepositoryFake{context: invContext, mappings: []store.DataSourceMapping{prometheusMapping, duplicatePrometheusMapping, lokiMapping, runtimeMapping}}
	runtime := &collectionRuntimeFake{}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{
		LokiConnector: &collectionLokiFake{result: validCollectionLokiResult(t)}, RuntimeConnector: runtime,
		Now: func() time.Time { return now }, RetryDelay: func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(runtime.calls) != 0 || len(repository.persistedRuntime) != 0 || len(repository.persistedGaps) != 3 || repository.completeCalls != 1 {
		t.Fatalf("runtime calls=%d runtime evidence=%d gaps=%d completion=%d", len(runtime.calls), len(repository.persistedRuntime), len(repository.persistedGaps), repository.completeCalls)
	}
	for _, record := range repository.persistedGaps {
		if record.SourceType != evidence.SourceRuntime {
			t.Fatalf("non-runtime gap persisted for ambiguous backing mappings: %+v", record)
		}
		var summary map[string]any
		if err := jsonUnmarshal(record.ValueSummary, &summary); err != nil {
			t.Fatal(err)
		}
		if summary["reason_code"] != string(evidence.CollectionFailureRequestRejected) {
			t.Fatalf("ambiguous backing mapping gap = %#v", summary)
		}
	}
}

func TestCollectionWorkerDoesNotRunRuntimeWhenBundleAuthorizationIsIncomplete(t *testing.T) {
	invContext, prometheusMapping := validCollectionContextAndMapping()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	invContext.Alert.StartsAt = now.Add(-3 * time.Minute)
	lokiMapping, runtimeMapping := validWorkerRuntimeMappings()
	runtimeMapping.Templates = runtimeMapping.Templates[:2]
	repository := &collectionRepositoryFake{context: invContext, mappings: []store.DataSourceMapping{prometheusMapping, lokiMapping, runtimeMapping}}
	runtime := &collectionRuntimeFake{}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{
		LokiConnector: &collectionLokiFake{result: validCollectionLokiResult(t)}, RuntimeConnector: runtime, Now: func() time.Time { return now }, RetryDelay: func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(runtime.calls) != 0 || len(repository.persistedRuntime) != 0 || len(repository.persistedGaps) != 2 || repository.completeCalls != 1 {
		t.Fatalf("runtime calls=%d runtime evidence=%d gaps=%d completion=%d", len(runtime.calls), len(repository.persistedRuntime), len(repository.persistedGaps), repository.completeCalls)
	}
	for _, record := range repository.persistedGaps {
		if record.SourceType != evidence.SourceRuntime {
			t.Fatalf("non-runtime gap persisted for runtime authorization failure: %+v", record)
		}
		var summary map[string]any
		if err := jsonUnmarshal(record.ValueSummary, &summary); err != nil {
			t.Fatal(err)
		}
		if summary["reason_code"] != string(evidence.CollectionFailureRequestRejected) {
			t.Fatalf("runtime authorization gap = %#v", summary)
		}
	}
}

func TestCollectionWorkerPersistsRuntimeCollectionFailureGaps(t *testing.T) {
	invContext, prometheusMapping := validCollectionContextAndMapping()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	invContext.Alert.StartsAt = now.Add(-3 * time.Minute)
	lokiMapping, runtimeMapping := validWorkerRuntimeMappings()
	repository := &collectionRepositoryFake{context: invContext, mappings: []store.DataSourceMapping{prometheusMapping, lokiMapping, runtimeMapping}}
	runtime := &collectionRuntimeFake{err: errors.New("remote response contained private address and credential")}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{
		LokiConnector: &collectionLokiFake{result: validCollectionLokiResult(t)}, RuntimeConnector: runtime,
		Now: func() time.Time { return now }, RetryDelay: func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(runtime.calls) != 1 || len(repository.persistedRuntime) != 0 || len(repository.persistedGaps) != 3 || repository.completeCalls != 1 {
		t.Fatalf("runtime calls=%d runtime evidence=%d gaps=%d completion=%d", len(runtime.calls), len(repository.persistedRuntime), len(repository.persistedGaps), repository.completeCalls)
	}
	for _, record := range repository.persistedGaps {
		if record.SourceType != evidence.SourceRuntime {
			t.Fatalf("non-runtime gap persisted for runtime query failure: %+v", record)
		}
		var summary map[string]any
		if err := jsonUnmarshal(record.ValueSummary, &summary); err != nil {
			t.Fatal(err)
		}
		if summary["reason_code"] != string(evidence.CollectionFailureUnavailable) || strings.Contains(string(record.ValueSummary), "private-address") {
			t.Fatalf("runtime query failure leaked or had wrong code: %#v", summary)
		}
	}
}

func TestCollectionWorkerRetriesWhenRuntimeEvidenceCannotBePersisted(t *testing.T) {
	invContext, prometheusMapping := validCollectionContextAndMapping()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	invContext.Alert.StartsAt = now.Add(-3 * time.Minute)
	prometheusMapping.PublicSettings.Endpoint = "https://prometheus.example.test"
	lokiMapping, runtimeMapping := validWorkerRuntimeMappings()
	repository := &collectionRepositoryFake{context: invContext, mappings: []store.DataSourceMapping{prometheusMapping, lokiMapping, runtimeMapping}, runtimePersistErr: errors.New("database unavailable")}
	runtime := &collectionRuntimeFake{result: runtimeconnector.Result{
		Runtime: datasource.RuntimeDockerCompose, Service: "orders-api", Environment: "prod", HostID: "demo-host", MappingVersion: runtimeMapping.Version,
	}}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{
		LokiConnector: &collectionLokiFake{result: validCollectionLokiResult(t)}, RuntimeConnector: runtime,
		Now: func() time.Time { return now }, RetryDelay: func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("NewCollectionProcessor: %v", err)
	}
	err = processor.Process(context.Background(), validCollectionJob())
	if err == nil || repository.retryCalls != 1 || repository.retryCode != "evidence_persist_failed" || repository.completeCalls != 0 {
		t.Fatalf("Process err=%v retry=%d code=%q complete=%d", err, repository.retryCalls, repository.retryCode, repository.completeCalls)
	}
}

func validWorkerRuntimeMappings() (store.DataSourceMapping, store.DataSourceMapping) {
	loki := store.DataSourceMapping{
		ID: "70000000-0000-4000-8000-000000000001", ProjectID: collectionProjectID, ServiceID: collectionServiceID,
		Environment: "prod", SourceType: datasource.SourceLoki,
		PublicSettings: datasource.PublicSettings{Endpoint: "https://loki.example.test"},
		Templates: []datasource.Template{
			{ID: "loki.service.slow_queries.v1", Version: 1, Source: datasource.SourceLoki},
			{ID: "loki.container.restarts.v1", Version: 1, Source: datasource.SourceLoki},
		}, Version: 4,
	}
	runtimeMapping := store.DataSourceMapping{
		ID: "80000000-0000-4000-8000-000000000001", ProjectID: collectionProjectID, ServiceID: collectionServiceID,
		Environment: "prod", SourceType: datasource.SourceRuntime, RuntimeType: datasource.RuntimeDockerCompose,
		PublicSettings: datasource.PublicSettings{
			Endpoint:      "https://cadvisor.example.test",
			RuntimeLabels: map[string]string{"project": "orders", "service": "orders-api", "env": "prod", "host_id": "demo-host", "container_id": "inventory"},
		},
		Templates: []datasource.Template{
			{ID: "runtime.containers.v1", Version: 1, Source: datasource.SourceRuntime},
			{ID: "runtime.host.v1", Version: 1, Source: datasource.SourceRuntime},
			{ID: "runtime.events.v1", Version: 1, Source: datasource.SourceRuntime},
		}, Version: 5,
	}
	return loki, runtimeMapping
}

type collectionRuntimeFake struct {
	result       runtimeconnector.Result
	err          error
	mutateResult func(*runtimeconnector.Result)
	calls        []struct {
		target  runtimeconnector.Target
		request runtimeconnector.Request
	}
}

func (collector *collectionRuntimeFake) Query(_ context.Context, target runtimeconnector.Target, request runtimeconnector.Request) (runtimeconnector.Result, error) {
	collector.calls = append(collector.calls, struct {
		target  runtimeconnector.Target
		request runtimeconnector.Request
	}{target: target, request: request})
	result := collector.result
	result.Start, result.End = request.Start, request.End
	if collector.mutateResult != nil {
		collector.mutateResult(&result)
	}
	return result, collector.err
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
