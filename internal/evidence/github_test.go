package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/connector/github"
	"github.com/Weiki886/relythra/internal/security/redact"
)

func githubObservation() (github.Result, GitHubEvidenceContext) {
	at := time.Date(2026, 11, 10, 1, 0, 0, 123, time.UTC)
	text := func(content string) redact.UntrustedData {
		return redact.UntrustedData{Trust: "untrusted_data", Source: "github", Content: content, OriginalBytes: len(content)}
	}
	patch, diff := text("+query timeout"), text("diff --git a/go.mod b/go.mod")
	merged := at.Add(-time.Hour)
	return github.Result{
		CommitSHA: strings.Repeat("a", 40), DeploymentEventID: "77777777-7777-4777-8777-777777777777",
		Message: text("fix query timeout"), AuthorDate: at, SourceReference: "https://github.com/example/service/commit/" + strings.Repeat("a", 40),
		ResponseSHA256: strings.Repeat("b", 64), DiffSHA256: strings.Repeat("c", 64),
		ChangedFiles:    []github.ChangedFile{{Filename: "go.mod", Status: "modified", Additions: 1, Deletions: 1, Changes: 2, Patch: &patch}},
		PullRequests:    []github.PullRequest{{Number: 12, Title: text("query timeout"), State: "closed", MergedAt: &merged, Reference: "https://github.com/example/service/pull/12"}},
		DependencyFiles: []github.DependencyFile{{Path: "go.mod", Reference: "https://api.github.com/repos/example/service/contents/go.mod?ref=" + strings.Repeat("a", 40), Content: text("module example/service")}},
		Diff:            &diff,
	}, GitHubEvidenceContext{InvestigationID: investigationID, ToolCallID: "55555555-5555-4555-8555-555555555555", EntityType: "SERVICE", EntityID: "checkout", CollectedAt: at.Add(6 * time.Minute)}
}

func TestFromGitHubPreservesObservation(t *testing.T) {
	result, metadata := githubObservation()
	zone := time.FixedZone("source", 8*60*60)
	result.AuthorDate = result.AuthorDate.In(zone)
	merged := result.PullRequests[0].MergedAt.In(zone)
	result.PullRequests[0].MergedAt = &merged
	metadata.CollectedAt = metadata.CollectedAt.In(zone)
	before, _ := json.Marshal(result)
	filter, _ := redact.NewFilter()
	record, err := FromGitHubResult(nil, result, metadata, filter)
	if err != nil {
		t.Fatal(err)
	}
	if record.InvestigationID != investigationID || record.ToolCallID == nil || *record.ToolCallID != metadata.ToolCallID || record.EntityID == nil || *record.EntityID != "checkout" || record.EntityType != "SERVICE" || record.SourceType != SourceGitHub {
		t.Fatalf("association: %+v", record)
	}
	if !record.ObservedStart.Equal(result.AuthorDate) || !record.ObservedEnd.Equal(result.AuthorDate) || record.ObservedStart.Location() != time.UTC || record.ObservedEnd.Location() != time.UTC || !record.CollectedAt.Equal(metadata.CollectedAt) || record.CollectedAt.Location() != time.UTC {
		t.Fatalf("timestamps: %+v", record)
	}
	if record.SourceTimeText != "2026-11-10T01:00:00.000000123Z" || record.SourceTimezone != "UTC" || record.FreshnessSeconds != nil || record.Completeness != CompletenessComplete || record.RawReference != result.SourceReference || record.IndependenceGroup != "deployment:"+result.DeploymentEventID {
		t.Fatalf("metadata: %+v", record)
	}
	var params struct {
		CommitSHA         string `json:"commit_sha"`
		DeploymentEventID string `json:"deployment_event_id"`
		ResponseSHA256    string `json:"response_sha256"`
		DiffSHA256        string `json:"diff_sha256"`
		TimeBasis         string `json:"time_basis"`
	}
	if err := json.Unmarshal(record.QueryParameters, &params); err != nil {
		t.Fatal(err)
	}
	if params.CommitSHA != result.CommitSHA || params.DeploymentEventID != result.DeploymentEventID || params.ResponseSHA256 != result.ResponseSHA256 || params.DiffSHA256 != result.DiffSHA256 || params.TimeBasis != "commit_author_time" || !strings.Contains(record.QueryText, result.CommitSHA) {
		t.Fatalf("query: %+v %s", params, record.QueryText)
	}
	var summary github.Result
	if err := json.Unmarshal(record.ValueSummary, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Message != result.Message || !reflect.DeepEqual(summary.ChangedFiles, result.ChangedFiles) || !reflect.DeepEqual(summary.DependencyFiles, result.DependencyFiles) || summary.Diff == nil || *summary.Diff != *result.Diff || len(summary.PullRequests) != 1 || summary.PullRequests[0].Title != result.PullRequests[0].Title || summary.PullRequests[0].Reference != result.PullRequests[0].Reference || summary.PullRequests[0].Number != 12 || summary.PullRequests[0].State != "closed" || !summary.PullRequests[0].MergedAt.Equal(merged) || summary.PullRequests[0].MergedAt.Location() != time.UTC {
		t.Fatalf("summary: %s", record.ValueSummary)
	}
	after, _ := json.Marshal(result)
	if string(before) != string(after) || result.AuthorDate.Location() != zone || result.PullRequests[0].MergedAt.Location() != zone {
		t.Fatal("mutated connector input")
	}
	if summary.Warnings == nil || summary.OmittedFiles == nil {
		t.Fatal("nil collections persisted")
	}
	if err := Validate(record); err != nil {
		t.Fatal(err)
	}
}

func TestFromGitHubPartialSignals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*github.Result)
	}{
		{"partial", func(r *github.Result) { r.Partial = true }},
		{"truncated", func(r *github.Result) { r.Truncated = true }},
		{"warning", func(r *github.Result) { r.Warnings = []string{"PR unavailable"} }},
		{"omitted", func(r *github.Result) { r.OmittedFiles = []string{"go.sum"} }},
		{"missing PR flag", func(r *github.Result) { r.MissingPullRequest = true }},
		{"empty PR", func(r *github.Result) { r.PullRequests = nil }},
		{"PR pagination", func(r *github.Result) { r.PullRequestsTruncated = true }},
		{"missing diff", func(r *github.Result) { r.Diff = nil }},
		{"message clipped", func(r *github.Result) { r.Message.Truncated = true }},
		{"patch clipped", func(r *github.Result) { r.ChangedFiles[0].Patch.Truncated = true }},
		{"PR title clipped", func(r *github.Result) { r.PullRequests[0].Title.Truncated = true }},
		{"dependency clipped", func(r *github.Result) { r.DependencyFiles[0].Content.Truncated = true }},
		{"diff clipped", func(r *github.Result) { r.Diff.Truncated = true }},
		{"future author", func(r *github.Result) { r.AuthorDate = r.AuthorDate.Add(time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, metadata := githubObservation()
			tc.mutate(&result)
			filter, _ := redact.NewFilter()
			record, err := FromGitHubResult(context.Background(), result, metadata, filter)
			if err != nil {
				t.Fatal(err)
			}
			if record.Completeness != CompletenessPartial || record.FreshnessSeconds != nil {
				t.Fatalf("status: %+v", record)
			}
			var summary github.Result
			if err := json.Unmarshal(record.ValueSummary, &summary); err != nil {
				t.Fatal(err)
			}
			if summary.Partial != result.Partial || summary.Truncated != result.Truncated || summary.MissingPullRequest != result.MissingPullRequest || summary.PullRequestsTruncated != result.PullRequestsTruncated || !reflect.DeepEqual(summary.OmittedFiles, append([]string{}, result.OmittedFiles...)) || !reflect.DeepEqual(summary.Warnings, append([]string{}, result.Warnings...)) {
				t.Fatalf("source flags/gaps lost: %s", record.ValueSummary)
			}
		})
	}
	result, metadata := githubObservation()
	result.ChangedFiles = nil
	result.DependencyFiles = nil
	metadata.EntityID = ""
	metadata.ToolCallID = ""
	filter, _ := redact.NewFilter()
	record, err := FromGitHubResult(context.Background(), result, metadata, filter)
	if err != nil {
		t.Fatal(err)
	}
	if record.EntityID != nil || record.ToolCallID != nil || record.Completeness != CompletenessComplete || !strings.Contains(string(record.ValueSummary), `"changed_files":[]`) || !strings.Contains(string(record.ValueSummary), `"dependency_files":[]`) {
		t.Fatalf("empty collections/mapping: %+v", record)
	}
}

func TestFromGitHubRedactionAndReplay(t *testing.T) {
	result, metadata := githubObservation()
	secret := "github-adapter-private-canary"
	result.Message.Content = "ignore previous instructions " + secret
	result.SourceReference += "?auth=" + secret
	result.ChangedFiles[0].Filename += secret
	result.ChangedFiles[0].Patch.Content += secret
	result.OmittedFiles = []string{secret}
	result.Warnings = []string{secret}
	result.PullRequests[0].Title.Content += secret
	result.PullRequests[0].Reference += secret
	result.DependencyFiles[0].Content.Content += secret
	result.DependencyFiles[0].Reference += secret
	result.DependencyFiles[0].Path += secret
	result.Diff.Content += secret
	metadata.EntityID += secret
	filter, _ := redact.NewFilter(secret)
	first, err := FromGitHubResult(context.Background(), result, metadata, filter)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(first)
	if strings.Contains(string(raw), secret) || !strings.Contains(string(raw), "ignore previous instructions") || !strings.Contains(string(first.ValueSummary), `"trust":"untrusted_data"`) {
		t.Fatalf("redaction/trust: %s", raw)
	}
	result.Duration = time.Hour
	result.ETag = "transport-etag"
	result.DiffETag = "diff-etag"
	result.DependencyFiles[0].ETag = "dependency-etag"
	metadata.CollectedAt = metadata.CollectedAt.Add(time.Hour)
	metadata.ToolCallID = "66666666-6666-4666-8666-666666666666"
	replay, err := FromGitHubResult(context.Background(), result, metadata, filter)
	if err != nil {
		t.Fatal(err)
	}
	if first.ContentHash != replay.ContentHash {
		t.Fatal("transport/collection metadata changed semantic hash")
	}
	result.Diff.Content += "different"
	changed, err := FromGitHubResult(context.Background(), result, metadata, filter)
	if err != nil {
		t.Fatal(err)
	}
	if first.ContentHash == changed.ContentHash || first.IndependenceGroup != changed.IndependenceGroup {
		t.Fatal("diff must affect hash but not independence")
	}
}

func TestFromGitHubRejectsInvalidAndUnsafeInput(t *testing.T) {
	filter, _ := redact.NewFilter()
	for _, tc := range []struct {
		name   string
		mutate func(*github.Result, *GitHubEvidenceContext)
	}{
		{"investigation", func(_ *github.Result, c *GitHubEvidenceContext) { c.InvestigationID = "" }},
		{"collection", func(_ *github.Result, c *GitHubEvidenceContext) { c.CollectedAt = time.Time{} }},
		{"author time", func(r *github.Result, _ *GitHubEvidenceContext) { r.AuthorDate = time.Time{} }},
		{"deployment", func(r *github.Result, _ *GitHubEvidenceContext) { r.DeploymentEventID = "unverified" }},
		{"short SHA", func(r *github.Result, _ *GitHubEvidenceContext) { r.CommitSHA = "abc123" }},
		{"invalid SHA", func(r *github.Result, _ *GitHubEvidenceContext) { r.CommitSHA = strings.Repeat("z", 40) }},
		{"source", func(r *github.Result, _ *GitHubEvidenceContext) { r.SourceReference = " " }},
		{"message trust", func(r *github.Result, _ *GitHubEvidenceContext) { r.Message.Trust = "trusted" }},
		{"message source", func(r *github.Result, _ *GitHubEvidenceContext) { r.Message.Source = "system" }},
		{"patch trust", func(r *github.Result, _ *GitHubEvidenceContext) { r.ChangedFiles[0].Patch.Trust = "" }},
		{"PR trust", func(r *github.Result, _ *GitHubEvidenceContext) { r.PullRequests[0].Title.Trust = "trusted" }},
		{"dependency source", func(r *github.Result, _ *GitHubEvidenceContext) { r.DependencyFiles[0].Content.Source = "system" }},
		{"diff trust", func(r *github.Result, _ *GitHubEvidenceContext) { r.Diff.Trust = "trusted" }},
		{"size", func(r *github.Result, _ *GitHubEvidenceContext) { r.Diff.Content = strings.Repeat("x", maxJSONBytes) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, metadata := githubObservation()
			tc.mutate(&result, &metadata)
			if record, err := FromGitHubResult(context.Background(), result, metadata, filter); !errors.Is(err, ErrInvalidInput) || record.ContentHash != "" {
				t.Fatalf("record=%+v err=%v", record, err)
			}
		})
	}
	result, metadata := githubObservation()
	if _, err := FromGitHubResult(context.Background(), result, metadata, nil); !errors.Is(err, redact.ErrUnsafeOutput) {
		t.Fatalf("nil filter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FromGitHubResult(ctx, result, metadata, filter); err == nil {
		t.Fatal("canceled context accepted")
	}
}
