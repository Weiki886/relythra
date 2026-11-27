package worker_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	githubconnector "github.com/Weiki886/relythra/internal/connector/github"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/store"
	"github.com/Weiki886/relythra/internal/worker"
)

type githubCollectionRepositoryFake struct {
	*collectionRepositoryFake
	candidates []store.DeploymentEvent
	persisted  []githubconnector.Result
}

func (repository *githubCollectionRepositoryFake) ListInvestigationDeploymentCandidates(context.Context, string) ([]store.DeploymentEvent, error) {
	return repository.candidates, nil
}

func (repository *githubCollectionRepositoryFake) PersistGitHubEvidence(_ context.Context, result githubconnector.Result, metadata evidence.GitHubEvidenceContext, filter *redact.Filter) (store.Evidence, bool, error) {
	if repository.persistErr != nil {
		return store.Evidence{}, false, repository.persistErr
	}
	if _, err := evidence.FromGitHubResult(context.Background(), result, metadata, filter); err != nil {
		return store.Evidence{}, false, err
	}
	repository.persisted = append(repository.persisted, result)
	return store.Evidence{ID: "github-evidence"}, true, nil
}

type githubCollectionFake struct {
	results map[string]githubconnector.Result
	err     error
	calls   []struct {
		target githubconnector.Target
		query  githubconnector.Query
	}
}

func (connector *githubCollectionFake) Query(_ context.Context, target githubconnector.Target, query githubconnector.Query) (githubconnector.Result, error) {
	connector.calls = append(connector.calls, struct {
		target githubconnector.Target
		query  githubconnector.Query
	}{target: target, query: query})
	if connector.err != nil {
		return githubconnector.Result{}, connector.err
	}
	return connector.results[query.Revision.DeploymentEventID], nil
}

func TestCollectionWorkerPersistsGitHubEvidenceForEveryLinkedDeploymentCandidate(t *testing.T) {
	investigation, _ := validCollectionContextAndMapping()
	mapping := validCollectionGitHubMapping()
	first := store.DeploymentEvent{ID: "70000000-0000-4000-8000-000000000001", CommitSHA: strings.Repeat("a", 40)}
	second := store.DeploymentEvent{ID: "70000000-0000-4000-8000-000000000002", CommitSHA: strings.Repeat("b", 40)}
	repository := &githubCollectionRepositoryFake{
		collectionRepositoryFake: &collectionRepositoryFake{context: investigation, mappings: []store.DataSourceMapping{mapping}},
		candidates:               []store.DeploymentEvent{first, second},
	}
	connector := &githubCollectionFake{results: map[string]githubconnector.Result{
		first.ID: githubCollectionResult(first), second.ID: githubCollectionResult(second),
	}}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{GitHubConnector: connector})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(connector.calls) != 2 || len(repository.persisted) != 2 || repository.completeCalls != 1 {
		t.Fatalf("GitHub calls=%d persisted=%d completions=%d", len(connector.calls), len(repository.persisted), repository.completeCalls)
	}
	for index, expected := range []store.DeploymentEvent{first, second} {
		call := connector.calls[index]
		if call.target.Repository != "acme/orders" || call.target.Endpoint != mapping.PublicSettings.Endpoint ||
			call.query.Revision.Source != githubconnector.RevisionSourceDeploymentEvent ||
			call.query.Revision.DeploymentEventID != expected.ID || call.query.Revision.CommitSHA != expected.CommitSHA {
			t.Errorf("candidate %d query = %+v", index, call)
		}
		if repository.persisted[index].DeploymentEventID != expected.ID || repository.persisted[index].CommitSHA != expected.CommitSHA {
			t.Errorf("candidate %d persisted result = %+v", index, repository.persisted[index])
		}
	}
}

func TestCollectionWorkerRecordsGitHubGapWhenNoLinkedDeploymentCandidateExists(t *testing.T) {
	investigation, _ := validCollectionContextAndMapping()
	repository := &githubCollectionRepositoryFake{collectionRepositoryFake: &collectionRepositoryFake{
		context: investigation, mappings: []store.DataSourceMapping{validCollectionGitHubMapping()},
	}}
	connector := &githubCollectionFake{}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{GitHubConnector: connector})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	githubGaps := filterGitHubGaps(repository.persistedGaps)
	if len(connector.calls) != 0 || len(githubGaps) != len(validCollectionGitHubMapping().Templates) || repository.completeCalls != 1 {
		t.Fatalf("calls=%d GitHub gaps=%d completed=%d", len(connector.calls), len(githubGaps), repository.completeCalls)
	}
	for _, gap := range githubGaps {
		if collectionGapReason(t, gap.ValueSummary) != evidence.CollectionFailureMissingRevision {
			t.Errorf("unexpected GitHub gap: %+v", gap)
		}
	}
}

func TestCollectionWorkerRetriesGitHubFailureAfterPersistingGap(t *testing.T) {
	investigation, _ := validCollectionContextAndMapping()
	candidate := store.DeploymentEvent{ID: "70000000-0000-4000-8000-000000000001", CommitSHA: strings.Repeat("a", 40)}
	repository := &githubCollectionRepositoryFake{collectionRepositoryFake: &collectionRepositoryFake{
		context: investigation, mappings: []store.DataSourceMapping{validCollectionGitHubMapping()},
	}, candidates: []store.DeploymentEvent{candidate}}
	connector := &githubCollectionFake{err: &githubconnector.QueryError{Category: githubconnector.ErrorTimeout}}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{GitHubConnector: connector})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err == nil {
		t.Fatalf("Process error = %v, want scheduled retry", err)
	}
	if repository.retryCode != "github_timeout" || len(filterGitHubGaps(repository.persistedGaps)) != len(validCollectionGitHubMapping().Templates) || repository.completeCalls != 0 {
		t.Fatalf("retry=%q gaps=%d completed=%d", repository.retryCode, len(repository.persistedGaps), repository.completeCalls)
	}
}

func TestCollectionWorkerDoesNotCompleteWhenGitHubEvidencePersistenceFails(t *testing.T) {
	investigation, _ := validCollectionContextAndMapping()
	candidate := store.DeploymentEvent{ID: "70000000-0000-4000-8000-000000000001", CommitSHA: strings.Repeat("a", 40)}
	repository := &githubCollectionRepositoryFake{collectionRepositoryFake: &collectionRepositoryFake{
		context: investigation, mappings: []store.DataSourceMapping{validCollectionGitHubMapping()}, persistErr: errors.New("database unavailable"),
	}, candidates: []store.DeploymentEvent{candidate}}
	connector := &githubCollectionFake{results: map[string]githubconnector.Result{candidate.ID: githubCollectionResult(candidate)}}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{GitHubConnector: connector})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err == nil {
		t.Fatalf("Process error = %v, want scheduled retry", err)
	}
	if repository.completeCalls != 0 || repository.retryCode != "evidence_persist_failed" {
		t.Fatalf("completed=%d retry=%q", repository.completeCalls, repository.retryCode)
	}
}

func validCollectionGitHubMapping() store.DataSourceMapping {
	_, mapping := validCollectionContextAndMapping()
	mapping.SourceType = datasource.SourceGitHub
	mapping.PublicSettings.Endpoint = "https://api.github.com"
	mapping.PublicSettings.Repository = "acme/orders"
	mapping.Templates = []datasource.Template{
		{ID: "github.commits.v1", Version: 1, Source: datasource.SourceGitHub},
		{ID: "github.pull_requests.v1", Version: 1, Source: datasource.SourceGitHub},
		{ID: "github.diff.v1", Version: 1, Source: datasource.SourceGitHub},
	}
	return mapping
}

func githubCollectionResult(deployment store.DeploymentEvent) githubconnector.Result {
	return githubconnector.Result{
		CommitSHA: deployment.CommitSHA, DeploymentEventID: deployment.ID,
		Message:    redact.UntrustedData{Content: "deployment commit", Trust: "untrusted_data", Source: "github", OriginalBytes: 18},
		AuthorDate: time.Now().UTC().Add(-time.Hour), SourceReference: "https://github.com/acme/orders/commit/" + deployment.CommitSHA,
		ResponseSHA256: strings.Repeat("a", 64), DiffSHA256: strings.Repeat("b", 64),
		ChangedFiles: []githubconnector.ChangedFile{}, OmittedFiles: []string{}, PullRequests: []githubconnector.PullRequest{}, DependencyFiles: []githubconnector.DependencyFile{}, Warnings: []string{},
	}
}

func collectionGapReason(t *testing.T, summary []byte) evidence.CollectionFailureCode {
	t.Helper()
	var value struct {
		ReasonCode evidence.CollectionFailureCode `json:"reason_code"`
	}
	if err := json.Unmarshal(summary, &value); err != nil {
		t.Fatal(err)
	}
	return value.ReasonCode
}

func filterGitHubGaps(records []evidence.Record) []evidence.Record {
	filtered := make([]evidence.Record, 0)
	for _, record := range records {
		if record.SourceType == evidence.SourceGitHub {
			filtered = append(filtered, record)
		}
	}
	return filtered
}

func TestCollectionWorkerBoundsGitHubDeploymentCandidatesAndPersistsLimitGap(t *testing.T) {
	investigation, _ := validCollectionContextAndMapping()
	candidates := make([]store.DeploymentEvent, 20+1)
	results := make(map[string]githubconnector.Result, len(candidates))
	for index := range candidates {
		eventID := fmt.Sprintf("70000000-0000-4000-8000-%012d", index+1)
		sha := strings.Repeat("a", 40)
		candidates[index] = store.DeploymentEvent{ID: eventID, CommitSHA: sha}
		results[eventID] = githubCollectionResult(candidates[index])
	}
	repository := &githubCollectionRepositoryFake{collectionRepositoryFake: &collectionRepositoryFake{
		context: investigation, mappings: []store.DataSourceMapping{validCollectionGitHubMapping()},
	}, candidates: candidates}
	connector := &githubCollectionFake{results: results}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{GitHubConnector: connector})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(connector.calls) != 20 || len(repository.persisted) != 20 || repository.retryCalls != 0 || repository.completeCalls != 1 {
		t.Fatalf("calls=%d persisted=%d retries=%d completed=%d", len(connector.calls), len(repository.persisted), repository.retryCalls, repository.completeCalls)
	}
	var foundLimitGap bool
	for _, gap := range filterGitHubGaps(repository.persistedGaps) {
		if collectionGapReason(t, gap.ValueSummary) == evidence.CollectionFailureResultLimit {
			foundLimitGap = true
		}
	}
	if !foundLimitGap {
		t.Fatal("candidate limit did not create a structured GitHub gap")
	}
}

func TestCollectionWorkerRejectsIncompleteGitHubTemplateBundleWithoutQuerying(t *testing.T) {
	investigation, _ := validCollectionContextAndMapping()
	mapping := validCollectionGitHubMapping()
	mapping.Templates = mapping.Templates[:2]
	repository := &githubCollectionRepositoryFake{collectionRepositoryFake: &collectionRepositoryFake{
		context: investigation, mappings: []store.DataSourceMapping{mapping},
	}}
	connector := &githubCollectionFake{}
	filter, _ := redact.NewFilter()
	processor, err := worker.NewCollectionProcessor(repository, &collectionPrometheusFake{result: validCollectionPrometheusResult()}, collectionSecretResolverFake{}, filter, worker.CollectionOptions{GitHubConnector: connector})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.Process(context.Background(), validCollectionJob()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(connector.calls) != 0 || len(filterGitHubGaps(repository.persistedGaps)) != len([]string{"github.commits.v1", "github.pull_requests.v1", "github.diff.v1"}) || repository.completeCalls != 1 {
		t.Fatalf("calls=%d GitHub gaps=%d completed=%d", len(connector.calls), len(filterGitHubGaps(repository.persistedGaps)), repository.completeCalls)
	}
	for _, gap := range filterGitHubGaps(repository.persistedGaps) {
		if collectionGapReason(t, gap.ValueSummary) != evidence.CollectionFailureRequestRejected {
			t.Errorf("unexpected incomplete-bundle gap reason: %s", gap.ValueSummary)
		}
	}
}
