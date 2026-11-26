package worker_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	lokiconnector "github.com/Weiki886/relythra/internal/connector/loki"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/security/secrets"
	"github.com/Weiki886/relythra/internal/store"
	"github.com/Weiki886/relythra/internal/worker"
)

type collectionLokiFake struct {
	result         lokiconnector.Result
	err            error
	failTemplateID string
	mutateResult   func(*lokiconnector.Result)
	calls          []datasource.NormalizedQuery
	targets        []lokiconnector.Target
}

func (connector *collectionLokiFake) Query(_ context.Context, target lokiconnector.Target, query datasource.NormalizedQuery) (lokiconnector.Result, error) {
	connector.calls = append(connector.calls, query)
	connector.targets = append(connector.targets, target)
	if query.TemplateID == connector.failTemplateID {
		return lokiconnector.Result{}, &lokiconnector.QueryError{Category: lokiconnector.ErrorTimeout}
	}
	if connector.err != nil {
		return lokiconnector.Result{}, connector.err
	}
	result := connector.result
	result.TemplateID, result.TemplateVersion = query.TemplateID, query.Version
	result.Start, result.End = query.Start, query.End
	result.Direction, result.Limit = query.Direction, query.Limit
	if connector.mutateResult != nil {
		connector.mutateResult(&result)
	}
	return result, nil
}

func validCollectionLokiMapping() store.DataSourceMapping {
	_, mapping := validCollectionContextAndMapping()
	mapping.SourceType = datasource.SourceLoki
	mapping.PublicSettings.Endpoint = "https://loki.example.test"
	mapping.Templates = []datasource.Template{{ID: "loki.service.slow_queries.v1", Version: 1, Source: datasource.SourceLoki}}
	return mapping
}

func validCollectionLokiResult(t *testing.T) lokiconnector.Result {
	t.Helper()
	filter, _ := redact.NewFilter()
	line, err := filter.Untrusted(context.Background(), "loki", "slow query duration_ms=2000", 16*1024)
	if err != nil {
		t.Fatal(err)
	}
	return lokiconnector.Result{
		Query: "registered-logql", SourceReference: "https://loki.example.test/loki/api/v1/query_range",
		ResponseSHA256: strings.Repeat("a", 64),
		Entries:        []lokiconnector.Entry{{Timestamp: time.Now().UTC().Add(-time.Minute), Line: line, Labels: map[string]string{"service": "orders-api"}}},
	}
}

func newLokiCollectionProcessor(t *testing.T, repository *collectionRepositoryFake, connector *collectionLokiFake, resolver lokiconnector.SecretResolver, options worker.CollectionOptions) *worker.CollectionProcessor {
	t.Helper()
	filter, _ := redact.NewFilter()
	options.LokiConnector = connector
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, resolver, filter, options)
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func TestCollectionWorkerPersistsMappedLokiEvidence(t *testing.T) {
	ctx, _ := validCollectionContextAndMapping()
	mapping := validCollectionLokiMapping()
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{mapping}}
	connector := &collectionLokiFake{result: validCollectionLokiResult(t)}
	processor := newLokiCollectionProcessor(t, repository, connector, collectionSecretResolverFake{}, collectionOptions())
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatal(err)
	}
	if len(repository.persistedLoki) != 1 || repository.completeCalls != 1 || repository.completedBeforeSave {
		t.Fatalf("Loki=%d completed=%d early=%v", len(repository.persistedLoki), repository.completeCalls, repository.completedBeforeSave)
	}
	query := connector.calls[0]
	if query.Service != ctx.Service.Slug || query.Environment != *ctx.Environment || query.TemplateID != mapping.Templates[0].ID || query.Version != 1 || query.Direction != "backward" || query.Limit != 20 || query.Cursor != "" {
		t.Fatalf("unexpected fixed query: %+v", query)
	}
	if query.Start != ctx.Alert.StartsAt.Add(-5*time.Minute) || query.End.Sub(query.Start) > 2*time.Hour || connector.targets[0].Endpoint != mapping.PublicSettings.Endpoint {
		t.Fatalf("unexpected window or endpoint: %+v", query)
	}
	record := repository.persistedLoki[0]
	if record.SourceType != evidence.SourceLoki || (record.EntityID == nil || *record.EntityID != ctx.Service.ID) || record.InvestigationID != ctx.InvestigationID || record.Completeness != evidence.CompletenessComplete {
		t.Fatalf("unexpected Loki ownership/result: %+v", record)
	}
}

func TestCollectionWorkerLokiEmptyAndPartialResults(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		result lokiconnector.Result
		want   string
	}{
		{"empty", lokiconnector.Result{Query: "fixed", SourceReference: "https://loki.example.test", Empty: true}, evidence.CompletenessMissing},
		{"page", lokiconnector.Result{Query: "fixed", SourceReference: "https://loki.example.test", NextCursor: "opaque"}, evidence.CompletenessPartial},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx, _ := validCollectionContextAndMapping()
			repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{validCollectionLokiMapping()}}
			processor := newLokiCollectionProcessor(t, repository, &collectionLokiFake{result: scenario.result}, collectionSecretResolverFake{}, collectionOptions())
			if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
				t.Fatal(err)
			}
			if len(repository.persistedLoki) != 1 || repository.persistedLoki[0].Completeness != scenario.want {
				t.Fatalf("records=%+v", repository.persistedLoki)
			}
		})
	}
}

func TestCollectionWorkerBoundsLokiWindowAndPayload(t *testing.T) {
	ctx, _ := validCollectionContextAndMapping()
	now := time.Now().UTC()
	ctx.Alert.StartsAt = now.Add(-6 * time.Hour)
	result := validCollectionLokiResult(t)
	for i := 0; i < 20; i++ {
		entry := result.Entries[0]
		entry.Line.Content = strings.Repeat("<", 16*1024) // JSON escaping alone can exceed the Evidence budget.
		result.Entries = append(result.Entries, entry)
	}
	result.Entries = result.Entries[1:]
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{validCollectionLokiMapping()}}
	connector := &collectionLokiFake{result: result}
	options := collectionOptions()
	options.Now = func() time.Time { return now }
	processor := newLokiCollectionProcessor(t, repository, connector, collectionSecretResolverFake{}, options)
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatal(err)
	}
	if len(connector.calls) != 1 || connector.calls[0].End.Sub(connector.calls[0].Start) != 2*time.Hour {
		t.Fatalf("queries=%+v", connector.calls)
	}
	if len(repository.persistedLoki) != 1 || repository.persistedLoki[0].Completeness != evidence.CompletenessPartial || len(repository.persistedLoki[0].ValueSummary) > 64*1024 {
		t.Fatalf("unbounded/complete result=%+v", repository.persistedLoki)
	}
	if !strings.Contains(string(repository.persistedLoki[0].ValueSummary), "budget") || !strings.Contains(string(repository.persistedLoki[0].ValueSummary), "window") {
		t.Fatalf("missing clipping warnings=%s", repository.persistedLoki[0].ValueSummary)
	}
}

func TestCollectionWorkerLokiFailuresPreserveIndependentWork(t *testing.T) {
	ctx, prometheusMapping := validCollectionContextAndMapping()
	mapping := validCollectionLokiMapping()
	mapping.Templates = append(mapping.Templates, datasource.Template{ID: "loki.service.errors.v1", Version: 1, Source: datasource.SourceLoki})
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{mapping, prometheusMapping}}
	connector := &collectionLokiFake{result: validCollectionLokiResult(t), failTemplateID: mapping.Templates[0].ID}
	processor := newLokiCollectionProcessor(t, repository, connector, collectionSecretResolverFake{}, collectionOptions())
	if err := processor.Process(context.Background(), validCollectionJob()); err == nil {
		t.Fatal("want retry")
	}
	if len(connector.calls) != 2 || len(repository.persistedLoki) != 1 || len(repository.persistedPrometheus) != 1 || len(repository.persistedGaps) != 1 || repository.retryCode != "loki_timeout" || repository.completeCalls != 0 {
		t.Fatalf("calls=%d Loki=%d Prometheus=%d gaps=%d retry=%s completed=%d", len(connector.calls), len(repository.persistedLoki), len(repository.persistedPrometheus), len(repository.persistedGaps), repository.retryCode, repository.completeCalls)
	}
}

func TestCollectionWorkerLokiPersistenceFailureDoesNotComplete(t *testing.T) {
	ctx, _ := validCollectionContextAndMapping()
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{validCollectionLokiMapping()}, persistErr: errors.New("database unavailable")}
	processor := newLokiCollectionProcessor(t, repository, &collectionLokiFake{result: validCollectionLokiResult(t)}, collectionSecretResolverFake{}, collectionOptions())
	if err := processor.Process(context.Background(), validCollectionJob()); err == nil {
		t.Fatal("want retry")
	}
	if repository.retryCode != "evidence_persist_failed" || repository.completeCalls != 0 {
		t.Fatalf("retry=%s complete=%d", repository.retryCode, repository.completeCalls)
	}
}

func TestCollectionWorkerLokiUsesOneCredentialSnapshot(t *testing.T) {
	const canary = "opaque-loki-credential-canary"
	ctx, _ := validCollectionContextAndMapping()
	mapping := validCollectionLokiMapping()
	mapping.SecretRef = "env:LOKI_TOKEN"
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{mapping}}
	result := validCollectionLokiResult(t)
	result.Entries[0].Line.Content = "raw echoed value " + canary
	connector := &collectionLokiFake{result: result}
	calls := 0
	resolver := lokiResolverFunc(func(context.Context, secrets.Reference) (secrets.Secret, error) { calls++; return secrets.New(canary) })
	processor := newLokiCollectionProcessor(t, repository, connector, resolver, collectionOptions())
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || connector.targets[0].ResolvedSecret == nil || connector.targets[0].ResolvedSecret.Reveal() != canary {
		t.Fatalf("secret resolutions=%d", calls)
	}
	if strings.Contains(string(repository.persistedLoki[0].ValueSummary), canary) {
		t.Fatal("persisted Loki credential leaked")
	}
}

type lokiResolverFunc func(context.Context, secrets.Reference) (secrets.Secret, error)

func (resolver lokiResolverFunc) Resolve(ctx context.Context, ref secrets.Reference) (secrets.Secret, error) {
	return resolver(ctx, ref)
}

func TestCollectionWorkerLokiErrorsPersistStableGapsAndRetry(t *testing.T) {
	for _, scenario := range []struct {
		category lokiconnector.ErrorCategory
		reason   string
	}{
		{lokiconnector.ErrorTimeout, "timeout"},
		{lokiconnector.ErrorUnauthorized, "permission_denied"},
		{lokiconnector.ErrorRateLimited, "rate_limited"},
		{lokiconnector.ErrorPolicyRejected, "request_rejected"},
		{lokiconnector.ErrorInvalidResponse, "invalid_response"},
		{lokiconnector.ErrorNetwork, "unavailable"},
	} {
		t.Run(string(scenario.category), func(t *testing.T) {
			ctx, prometheusMapping := validCollectionContextAndMapping()
			repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{validCollectionLokiMapping(), prometheusMapping}}
			connector := &collectionLokiFake{err: &lokiconnector.QueryError{Category: scenario.category, Cause: errors.New("private-address-and-credential")}}
			processor := newLokiCollectionProcessor(t, repository, connector, collectionSecretResolverFake{}, collectionOptions())
			err := processor.Process(context.Background(), validCollectionJob())
			if err == nil || strings.Contains(err.Error(), "private-address") || repository.retryCode != "loki_"+string(scenario.category) || repository.completeCalls != 0 {
				t.Fatalf("err=%v retry=%q complete=%d", err, repository.retryCode, repository.completeCalls)
			}
			if len(repository.persistedGaps) != 1 || !strings.Contains(string(repository.persistedGaps[0].ValueSummary), `"reason_code":"`+scenario.reason+`"`) {
				t.Fatalf("gaps=%+v", repository.persistedGaps)
			}
		})
	}
}

func TestCollectionWorkerLokiMissingSecretNeverQueries(t *testing.T) {
	ctx, _ := validCollectionContextAndMapping()
	mapping := validCollectionLokiMapping()
	mapping.SecretRef = "env:MISSING_LOKI_TOKEN"
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{mapping}}
	connector := &collectionLokiFake{}
	processor := newLokiCollectionProcessor(t, repository, connector, collectionSecretResolverFake{}, collectionOptions())
	if err := processor.Process(context.Background(), validCollectionJob()); err == nil {
		t.Fatal("want secret retry")
	}
	if len(connector.calls) != 0 || repository.retryCode != "loki_secret_unavailable" || repository.completeCalls != 0 {
		t.Fatalf("calls=%d retry=%q", len(connector.calls), repository.retryCode)
	}
}

func TestCollectionWorkerLokiTemplateVersionMismatchHasRejectedGap(t *testing.T) {
	ctx, _ := validCollectionContextAndMapping()
	mapping := validCollectionLokiMapping()
	mapping.Templates[0].Version = 2
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{mapping}}
	connector := &collectionLokiFake{}
	processor := newLokiCollectionProcessor(t, repository, connector, collectionSecretResolverFake{}, collectionOptions())
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatal(err)
	}
	if len(connector.calls) != 0 || len(repository.persistedGaps) != 2 || !strings.Contains(string(repository.persistedGaps[0].ValueSummary), `"reason_code":"request_rejected"`) {
		t.Fatalf("calls=%d gaps=%+v", len(connector.calls), repository.persistedGaps)
	}
}

func TestCollectionWorkerClipsLokiPayloadAndRetainsBoundedLogPrefix(t *testing.T) {
	ctx, _ := validCollectionContextAndMapping()
	result := validCollectionLokiResult(t)
	entry := result.Entries[0]
	entry.Line.Content = strings.Repeat("<", 1024)
	result.Entries = make([]lokiconnector.Entry, 20)
	for i := range result.Entries {
		result.Entries[i] = entry
	}
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{validCollectionLokiMapping()}}
	processor := newLokiCollectionProcessor(t, repository, &collectionLokiFake{result: result}, collectionSecretResolverFake{}, collectionOptions())
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatal(err)
	}
	if len(repository.persistedLoki) != 1 {
		t.Fatalf("Loki records=%d", len(repository.persistedLoki))
	}
	record := repository.persistedLoki[0]
	var summary struct {
		Entries []lokiconnector.Entry `json:"entries"`
		Partial bool                  `json:"partial"`
	}
	if err := json.Unmarshal(record.ValueSummary, &summary); err != nil {
		t.Fatal(err)
	}
	if record.Completeness != evidence.CompletenessPartial || !summary.Partial || len(summary.Entries) == 0 || len(summary.Entries) >= 20 || len(record.ValueSummary) > 64*1024 {
		t.Fatalf("completeness=%s partial=%v entries=%d bytes=%d", record.Completeness, summary.Partial, len(summary.Entries), len(record.ValueSummary))
	}
}

func TestCollectionWorkerRejectsLokiResultOutsideRequestedScope(t *testing.T) {
	ctx, _ := validCollectionContextAndMapping()
	repository := &collectionRepositoryFake{context: ctx, mappings: []store.DataSourceMapping{validCollectionLokiMapping()}}
	connector := &collectionLokiFake{result: validCollectionLokiResult(t), mutateResult: func(result *lokiconnector.Result) { result.Start = result.Start.Add(-time.Hour) }}
	processor := newLokiCollectionProcessor(t, repository, connector, collectionSecretResolverFake{}, collectionOptions())
	if err := processor.Process(context.Background(), validCollectionJob()); err == nil {
		t.Fatal("want invalid-result retry")
	}
	if len(repository.persistedLoki) != 0 || repository.retryCode != "loki_invalid_response" || repository.completeCalls != 0 {
		t.Fatalf("Loki=%d retry=%q completed=%d", len(repository.persistedLoki), repository.retryCode, repository.completeCalls)
	}
}
