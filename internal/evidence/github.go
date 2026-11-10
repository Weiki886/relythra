package evidence

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/connector/github"
	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/security/redact"
)

// GitHubEvidenceContext supplies investigation ownership omitted by the connector result.
// The caller must associate the connector's verified deployment with this investigation.
type GitHubEvidenceContext struct {
	InvestigationID string
	ToolCallID      string
	EntityType      string
	EntityID        string
	CollectedAt     time.Time
}

type githubQueryParameters struct {
	CommitSHA         string `json:"commit_sha"`
	DeploymentEventID string `json:"deployment_event_id"`
	ResponseSHA256    string `json:"response_sha256"`
	DiffSHA256        string `json:"diff_sha256"`
	TimeBasis         string `json:"time_basis"`
}

type githubDependencySummary struct {
	Path      string               `json:"path"`
	Reference string               `json:"reference"`
	Content   redact.UntrustedData `json:"content"`
}

type githubValueSummary struct {
	Message               redact.UntrustedData      `json:"message"`
	ChangedFiles          []github.ChangedFile      `json:"changed_files"`
	OmittedFiles          []string                  `json:"omitted_files"`
	PullRequests          []github.PullRequest      `json:"pull_requests"`
	DependencyFiles       []githubDependencySummary `json:"dependency_files"`
	Diff                  *redact.UntrustedData     `json:"diff,omitempty"`
	Warnings              []string                  `json:"warnings"`
	Partial               bool                      `json:"partial"`
	Truncated             bool                      `json:"truncated"`
	MissingPullRequest    bool                      `json:"missing_pull_request"`
	PullRequestsTruncated bool                      `json:"pull_requests_truncated"`
}

// FromGitHubResult preserves one known commit and its available fragments. Missing
// subresources make it partial. Author time is not deployment time or freshness;
// no expiry is inferred for this immutable revision. Oversized snapshots fail
// normalization without silently discarding code or dependency evidence.
func FromGitHubResult(ctx context.Context, result github.Result, metadata GitHubEvidenceContext, filter *redact.Filter) (Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if filter == nil {
		return Record{}, redact.ErrUnsafeOutput
	}
	sha, err := hex.DecodeString(result.CommitSHA)
	if err != nil || len(sha) != 20 || !domain.IsID(result.DeploymentEventID) || result.AuthorDate.IsZero() || strings.TrimSpace(result.SourceReference) == "" {
		return Record{}, ErrInvalidInput
	}
	partial := result.Partial || result.Truncated || result.MissingPullRequest || result.PullRequestsTruncated || len(result.Warnings) > 0 || len(result.OmittedFiles) > 0 || len(result.PullRequests) == 0 || result.Diff == nil || result.AuthorDate.After(metadata.CollectedAt)
	// Check every text fragment, including optional ones, before serializing it.
	checkText := func(text redact.UntrustedData) bool {
		partial = partial || text.Truncated
		return text.Trust == "untrusted_data" && text.Source == "github"
	}
	if !checkText(result.Message) {
		return Record{}, ErrInvalidInput
	}
	if result.Diff != nil && !checkText(*result.Diff) {
		return Record{}, ErrInvalidInput
	}
	for _, file := range result.ChangedFiles {
		if file.Patch != nil && !checkText(*file.Patch) {
			return Record{}, ErrInvalidInput
		}
	}
	prs := make([]github.PullRequest, len(result.PullRequests))
	for index, pr := range result.PullRequests {
		if !checkText(pr.Title) {
			return Record{}, ErrInvalidInput
		}
		if pr.MergedAt != nil {
			merged := pr.MergedAt.UTC()
			pr.MergedAt = &merged
		}
		prs[index] = pr
	}
	dependencies := make([]githubDependencySummary, len(result.DependencyFiles))
	for index, file := range result.DependencyFiles {
		if !checkText(file.Content) {
			return Record{}, ErrInvalidInput
		}
		dependencies[index] = githubDependencySummary{Path: file.Path, Reference: file.Reference, Content: file.Content}
	}
	commitSHA := strings.ToLower(result.CommitSHA)
	parameters, err := json.Marshal(githubQueryParameters{
		CommitSHA: commitSHA, DeploymentEventID: result.DeploymentEventID, ResponseSHA256: result.ResponseSHA256, DiffSHA256: result.DiffSHA256, TimeBasis: "commit_author_time",
	})
	if err != nil {
		return Record{}, fmt.Errorf("%w: encode GitHub query metadata", ErrInvalidInput)
	}
	summary, err := json.Marshal(githubValueSummary{
		Message: result.Message, ChangedFiles: append([]github.ChangedFile{}, result.ChangedFiles...), OmittedFiles: append([]string{}, result.OmittedFiles...), PullRequests: prs, DependencyFiles: dependencies, Diff: result.Diff, Warnings: append([]string{}, result.Warnings...),
		Partial: result.Partial, Truncated: result.Truncated, MissingPullRequest: result.MissingPullRequest, PullRequestsTruncated: result.PullRequestsTruncated,
	})
	if err != nil {
		return Record{}, fmt.Errorf("%w: encode GitHub result", ErrInvalidInput)
	}
	completeness := CompletenessComplete
	if partial {
		completeness = CompletenessPartial
	}
	return Normalize(ctx, Input{
		InvestigationID: metadata.InvestigationID, ToolCallID: metadata.ToolCallID, SourceType: SourceGitHub, EntityType: metadata.EntityType, EntityID: metadata.EntityID,
		ObservedStart: result.AuthorDate, ObservedEnd: result.AuthorDate, CollectedAt: metadata.CollectedAt,
		QueryText: "commit " + commitSHA, RawReference: result.SourceReference, QueryParameters: parameters, ValueSummary: summary, Completeness: completeness,
		IndependenceGroup: "deployment:" + result.DeploymentEventID, SourceTimezone: "UTC", SourceTimeText: result.AuthorDate.UTC().Format(time.RFC3339Nano),
	}, filter)
}
