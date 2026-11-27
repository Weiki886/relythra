// Package github reads bounded GitHub commit evidence for verified deployments.
// It never executes repository content or accepts caller-provided API paths.
package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Weiki886/relythra/internal/domain"
	"github.com/Weiki886/relythra/internal/security/outbound"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/security/secrets"
)

const (
	DefaultTimeout              = 10 * time.Second
	MaxResponseBytes            = 4 << 20
	MaxChangedFileInventory     = 500
	DefaultMaxFiles             = 100
	MaxFiles                    = 500
	DefaultMaxDiffBytes         = 256 << 10
	MaxDiffBytes                = 1 << 20
	DefaultMaxPatchBytes        = 32 << 10
	MaxPatchBytes               = 128 << 10
	MaxTotalPatchBytes          = 1 << 20
	DefaultMaxDependencyBytes   = 64 << 10
	MaxDependencyFileBytes      = 256 << 10
	MaxCommitMessageBytes       = 16 << 10
	MaxPullRequests             = 20
	MaxDependencyFiles          = 50
	MaxRateLimitRetryAfter      = 24 * time.Hour
	githubRESTVersion           = "2022-11-28"
	githubJSONMediaType         = "application/vnd.github+json"
	githubDiffMediaType         = "application/vnd.github.diff"
	githubRawMediaType          = "application/vnd.github.raw+json"
	defaultPullRequestMediaType = "application/vnd.github+json"
)

var (
	ErrInvalidQuery        = errors.New("invalid GitHub query")
	ErrInvalidRevision     = errors.New("GitHub revision is not deployment-verified")
	ErrPolicyRejected      = errors.New("GitHub target rejected by outbound policy")
	ErrSecretUnavailable   = errors.New("GitHub credential unavailable")
	ErrTimeout             = errors.New("GitHub request timed out")
	ErrNetwork             = errors.New("GitHub request failed")
	ErrPermissionDenied    = errors.New("GitHub denied repository access")
	ErrRateLimited         = errors.New("GitHub rate limited the request")
	ErrRevisionUnavailable = errors.New("GitHub revision is unavailable")
	ErrRemoteUnavailable   = errors.New("GitHub returned an unsuccessful response")
	ErrInvalidResponse     = errors.New("GitHub response is invalid")
	ErrResponseTooLarge    = errors.New("GitHub response exceeds the size limit")

	commitSHAPattern  = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$`)
)

type ErrorCategory string

const (
	ErrorInvalidQuery        ErrorCategory = "invalid_query"
	ErrorInvalidRevision     ErrorCategory = "revision_not_deployment_verified"
	ErrorPolicyRejected      ErrorCategory = "policy_rejected"
	ErrorSecretUnavailable   ErrorCategory = "secret_unavailable"
	ErrorTimeout             ErrorCategory = "timeout"
	ErrorNetwork             ErrorCategory = "network_error"
	ErrorPermissionDenied    ErrorCategory = "permission_denied"
	ErrorRateLimited         ErrorCategory = "rate_limited"
	ErrorRevisionUnavailable ErrorCategory = "revision_unavailable"
	ErrorRemoteUnavailable   ErrorCategory = "remote_unavailable"
	ErrorInvalidResponse     ErrorCategory = "invalid_response"
	ErrorResponseTooLarge    ErrorCategory = "response_too_large"
)

type QueryError struct {
	Category       ErrorCategory
	Cause          error
	RetryAfter     time.Duration
	RateLimitReset time.Time
}

func (err *QueryError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return "GitHub query failed: " + string(err.Category)
}

func (err *QueryError) Unwrap() error { return err.Cause }

func IsErrorCategory(err error, category ErrorCategory) bool {
	var queryError *QueryError
	return errors.As(err, &queryError) && queryError.Category == category
}

type RevisionSource string

const RevisionSourceDeploymentEvent RevisionSource = "deployment_event"

type Revision struct {
	CommitSHA         string
	DeploymentEventID string
	Source            RevisionSource
}

type Target struct {
	Endpoint        string
	Repository      string
	SecretReference *secrets.Reference
	ResolvedSecret  *secrets.Secret
}

type Query struct {
	Revision               Revision
	MaxFiles               int
	MaxDiffBytes           int
	MaxPatchBytes          int
	MaxDependencyFileBytes int
}

type ChangedFile struct {
	Filename  string                `json:"filename"`
	Status    string                `json:"status"`
	Additions int                   `json:"additions"`
	Deletions int                   `json:"deletions"`
	Changes   int                   `json:"changes"`
	Patch     *redact.UntrustedData `json:"patch,omitempty"`
}

type PullRequest struct {
	Number    int                  `json:"number"`
	Title     redact.UntrustedData `json:"title"`
	State     string               `json:"state"`
	MergedAt  *time.Time           `json:"merged_at,omitempty"`
	Reference string               `json:"reference"`
}

type DependencyFile struct {
	Path      string               `json:"path"`
	Reference string               `json:"reference"`
	ETag      string               `json:"etag,omitempty"`
	Content   redact.UntrustedData `json:"content"`
}

type Result struct {
	CommitSHA             string                `json:"commit_sha"`
	DeploymentEventID     string                `json:"deployment_event_id"`
	Message               redact.UntrustedData  `json:"message"`
	AuthorDate            time.Time             `json:"author_date"`
	SourceReference       string                `json:"source_reference"`
	ETag                  string                `json:"etag,omitempty"`
	ResponseSHA256        string                `json:"response_sha256"`
	DiffSHA256            string                `json:"diff_sha256"`
	ChangedFiles          []ChangedFile         `json:"changed_files"`
	OmittedFiles          []string              `json:"omitted_files"`
	PullRequests          []PullRequest         `json:"pull_requests"`
	DependencyFiles       []DependencyFile      `json:"dependency_files"`
	Diff                  *redact.UntrustedData `json:"diff,omitempty"`
	DiffETag              string                `json:"diff_etag,omitempty"`
	Warnings              []string              `json:"warnings"`
	Duration              time.Duration         `json:"duration"`
	Partial               bool                  `json:"partial"`
	Truncated             bool                  `json:"truncated"`
	MissingPullRequest    bool                  `json:"missing_pull_request"`
	PullRequestsTruncated bool                  `json:"pull_requests_truncated"`
}

type SecretResolver interface {
	Resolve(context.Context, secrets.Reference) (secrets.Secret, error)
}

type targetPolicy interface {
	Validate(context.Context, string) (outbound.Target, error)
}

type Connector struct {
	policy   targetPolicy
	resolver SecretResolver
	filter   *redact.Filter
	client   *http.Client
}

type Option func(*optionConfig) error

type optionConfig struct{ timeout time.Duration }

func WithTimeout(timeout time.Duration) Option {
	return func(config *optionConfig) error {
		if timeout <= 0 || timeout > time.Minute {
			return errors.New("timeout must be between 1ns and 1m")
		}
		config.timeout = timeout
		return nil
	}
}

func NewConnector(policy *outbound.Policy, resolver SecretResolver, filter *redact.Filter, options ...Option) (*Connector, error) {
	if policy == nil || resolver == nil || filter == nil {
		return nil, errors.New("outbound policy, secret resolver, and redaction filter are required")
	}
	config := optionConfig{timeout: DefaultTimeout}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("GitHub connector option is nil")
		}
		if err := option(&config); err != nil {
			return nil, fmt.Errorf("configure GitHub connector: %w", err)
		}
	}
	client, err := outbound.NewHTTPClient(policy, config.timeout)
	if err != nil {
		return nil, fmt.Errorf("create GitHub HTTP client: %w", err)
	}
	return &Connector{policy: policy, resolver: resolver, filter: filter, client: client}, nil
}

func (connector *Connector) Query(ctx context.Context, target Target, query Query) (Result, error) {
	started := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	if connector == nil || connector.policy == nil || connector.resolver == nil || connector.filter == nil || connector.client == nil {
		return Result{}, queryError(ErrorInvalidQuery, ErrInvalidQuery)
	}
	query, err := normalizeQuery(target, query)
	if err != nil {
		category := ErrorInvalidQuery
		if errors.Is(err, ErrInvalidRevision) {
			category = ErrorInvalidRevision
		}
		return Result{}, queryError(category, err)
	}
	endpoint, err := parseEndpoint(target.Endpoint)
	if err != nil {
		return Result{}, queryError(ErrorPolicyRejected, err)
	}
	if _, err := connector.policy.Validate(ctx, target.Endpoint); err != nil {
		return Result{}, queryError(ErrorPolicyRejected, err)
	}
	credential := ""
	if target.ResolvedSecret != nil {
		credential = target.ResolvedSecret.Reveal()
	} else if target.SecretReference != nil {
		secret, err := connector.resolver.Resolve(ctx, *target.SecretReference)
		if err != nil {
			return Result{}, queryError(ErrorSecretUnavailable, err)
		}
		credential = secret.Reveal()
	}
	owner, repository, _ := strings.Cut(target.Repository, "/")
	basePath := strings.TrimRight(endpoint.EscapedPath(), "/")
	apiPath := func(parts ...string) string {
		encoded := make([]string, len(parts))
		for index, part := range parts {
			encoded[index] = url.PathEscape(part)
		}
		return basePath + "/" + strings.Join(encoded, "/")
	}
	query.Revision.CommitSHA = strings.ToLower(query.Revision.CommitSHA)
	commitPath := apiPath("repos", owner, repository, "commits", query.Revision.CommitSHA)
	commitBody, commitHeader, commit, inventory, inventoryTruncated, err := connector.fetchCommit(ctx, endpoint, credential, commitPath, query.Revision.CommitSHA)
	if err != nil {
		return Result{}, err
	}
	files, omitted, truncated, err := collectChangedFiles(ctx, connector.filter, inventory, query.MaxFiles, query.MaxPatchBytes)
	if err != nil {
		return Result{}, queryError(ErrorInvalidResponse, err)
	}
	message, err := connector.filter.Untrusted(ctx, "github", commit.Commit.Message, MaxCommitMessageBytes)
	if err != nil {
		return Result{}, queryError(ErrorInvalidResponse, err)
	}
	result := Result{
		CommitSHA:         query.Revision.CommitSHA,
		DeploymentEventID: query.Revision.DeploymentEventID,
		Message:           message,
		AuthorDate:        commit.Commit.Author.Date.UTC(),
		SourceReference:   safeSourceReference(commit.HTMLURL, endpoint, commitPath),
		ETag:              commitHeader.Get("ETag"),
		ResponseSHA256:    bodyDigest(commitBody),
		ChangedFiles:      files,
		OmittedFiles:      omitted,
		PullRequests:      []PullRequest{},
		DependencyFiles:   []DependencyFile{},
		Warnings:          []string{},
		Truncated:         truncated || inventoryTruncated,
	}
	if truncated || inventoryTruncated {
		result.Partial = true
		result.Warnings = append(result.Warnings, "Changed file inventory reached the configured file cap.")
	}

	pullRequests, pullRequestsTruncated, err := connector.fetchPullRequests(
		ctx, endpoint, credential,
		apiPath("repos", owner, repository, "commits", query.Revision.CommitSHA, "pulls"),
	)
	if err != nil {
		if IsErrorCategory(err, ErrorRevisionUnavailable) {
			result.Partial = true
			result.Warnings = append(result.Warnings, "Associated pull requests are unavailable for this commit.")
		} else {
			return Result{}, err
		}
	} else {
		result.PullRequests = pullRequests
		result.PullRequestsTruncated = pullRequestsTruncated
		if pullRequestsTruncated {
			result.Partial = true
			result.Truncated = true
			result.Warnings = append(result.Warnings, "Associated pull request list was truncated at the configured cap.")
		}
		result.MissingPullRequest = len(pullRequests) == 0
		if result.MissingPullRequest {
			result.Partial = true
			result.Warnings = append(result.Warnings, "No pull request is associated with this commit.")
		}
	}

	diffBytes, diffHeader, diffTransportTruncated, err := connector.getTruncated(ctx, endpoint, credential, commitPath, githubDiffMediaType, query.MaxDiffBytes)
	if err != nil {
		return Result{}, err
	}
	result.DiffSHA256 = bodyDigest(diffBytes)
	if !utf8.Valid(diffBytes) {
		result.Partial = true
		result.Warnings = append(result.Warnings, "Commit diff contains non-text data and was omitted.")
		result.Duration = time.Since(started)
		return result, nil
	}
	diff, err := connector.filter.Untrusted(ctx, "github", string(diffBytes), query.MaxDiffBytes)
	if err != nil {
		return Result{}, queryError(ErrorInvalidResponse, err)
	}
	diff.Truncated = diff.Truncated || diffTransportTruncated
	if diffTransportTruncated {
		diff.OriginalBytes = query.MaxDiffBytes + 1
	}
	result.Diff = &diff
	result.DiffETag = diffHeader.Get("ETag")
	if diffTransportTruncated || diff.Truncated {
		result.Partial = true
		result.Truncated = true
		result.Warnings = append(result.Warnings, "Commit diff was truncated at the configured byte limit.")
	}

	for _, file := range files {
		if !isDependencyFile(file.Filename) {
			continue
		}
		if len(result.DependencyFiles) == MaxDependencyFiles {
			result.Partial = true
			result.Truncated = true
			result.OmittedFiles = append(result.OmittedFiles, file.Filename)
			continue
		}
		filePath := apiPath("repos", owner, repository, "contents") + "/" + escapeRepoPath(file.Filename) + "?ref=" + url.QueryEscape(query.Revision.CommitSHA)
		contentBytes, contentHeader, contentTransportTruncated, err := connector.getTruncated(ctx, endpoint, credential, filePath, githubRawMediaType, query.MaxDependencyFileBytes)
		if err != nil {
			if IsErrorCategory(err, ErrorRevisionUnavailable) {
				result.Partial = true
				result.OmittedFiles = append(result.OmittedFiles, file.Filename)
				result.Warnings = append(result.Warnings, "A dependency file at the deployment revision is unavailable.")
				continue
			}
			return Result{}, err
		}
		if !utf8.Valid(contentBytes) {
			result.Partial = true
			result.OmittedFiles = append(result.OmittedFiles, file.Filename)
			result.Warnings = append(result.Warnings, "A non-text dependency file was omitted.")
			continue
		}
		content, err := connector.filter.Untrusted(ctx, "github", string(contentBytes), query.MaxDependencyFileBytes)
		if err != nil {
			return Result{}, queryError(ErrorInvalidResponse, err)
		}
		content.Truncated = content.Truncated || contentTransportTruncated
		if contentTransportTruncated {
			content.OriginalBytes = query.MaxDependencyFileBytes + 1
		}
		result.DependencyFiles = append(result.DependencyFiles, DependencyFile{
			Path:      file.Filename,
			Reference: safeSourceReference("", endpoint, filePath),
			ETag:      contentHeader.Get("ETag"),
			Content:   content,
		})
		if contentTransportTruncated || content.Truncated {
			result.Partial = true
			result.Truncated = true
			result.Warnings = append(result.Warnings, "A dependency file was truncated at the configured byte limit.")
		}
	}
	result.Duration = time.Since(started)
	return result, nil
}

func normalizeQuery(target Target, query Query) (Query, error) {
	if !repositoryPattern.MatchString(target.Repository) || target.Endpoint == "" {
		return Query{}, ErrInvalidQuery
	}
	if query.Revision.Source != RevisionSourceDeploymentEvent || !domain.IsID(query.Revision.DeploymentEventID) ||
		!commitSHAPattern.MatchString(query.Revision.CommitSHA) {
		return Query{}, ErrInvalidRevision
	}
	if query.MaxFiles == 0 {
		query.MaxFiles = DefaultMaxFiles
	}
	if query.MaxDiffBytes == 0 {
		query.MaxDiffBytes = DefaultMaxDiffBytes
	}
	if query.MaxPatchBytes == 0 {
		query.MaxPatchBytes = DefaultMaxPatchBytes
	}
	if query.MaxDependencyFileBytes == 0 {
		query.MaxDependencyFileBytes = DefaultMaxDependencyBytes
	}
	if query.MaxFiles < 1 || query.MaxFiles > MaxFiles || query.MaxDiffBytes < 1 || query.MaxDiffBytes > MaxDiffBytes ||
		query.MaxPatchBytes < 1 || query.MaxPatchBytes > MaxPatchBytes ||
		query.MaxDependencyFileBytes < 1 || query.MaxDependencyFileBytes > MaxDependencyFileBytes {
		return Query{}, ErrInvalidQuery
	}
	query.Revision.CommitSHA = strings.ToLower(query.Revision.CommitSHA)
	return query, nil
}

func parseEndpoint(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || endpoint == nil || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.EscapedPath() != "" && endpoint.EscapedPath() != "/") {
		return nil, outbound.ErrInvalidTarget
	}
	return endpoint, nil
}

type rawCommit struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Commit  struct {
		Message string `json:"message"`
		Author  struct {
			Date time.Time `json:"date"`
		} `json:"author"`
	} `json:"commit"`
	Files []rawChangedFile `json:"files"`
}

type rawChangedFile struct {
	Filename  string `json:"filename"`
	Status    string `json:"status"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	Changes   int    `json:"changes"`
	Patch     string `json:"patch"`
}

func decodeCommit(body []byte, expectedSHA string) (rawCommit, error) {
	var commit rawCommit
	if err := json.Unmarshal(body, &commit); err != nil || !strings.EqualFold(commit.SHA, expectedSHA) || commit.Commit.Message == "" || commit.Commit.Author.Date.IsZero() {
		return rawCommit{}, errors.New("commit response is invalid or does not match the requested revision")
	}
	return commit, nil
}

func (connector *Connector) fetchCommit(
	ctx context.Context,
	endpoint *url.URL,
	credential string,
	commitPath string,
	expectedSHA string,
) ([]byte, http.Header, rawCommit, []rawChangedFile, bool, error) {
	var digestMaterial []byte
	var firstHeader http.Header
	var metadata rawCommit
	files := make([]rawChangedFile, 0)
	truncated := false
	for page := 1; page <= MaxChangedFileInventory/100; page++ {
		pagePath := commitPath + "?page=" + strconv.Itoa(page) + "&per_page=100"
		body, headers, err := connector.get(ctx, endpoint, credential, pagePath, githubJSONMediaType)
		if err != nil {
			return nil, nil, rawCommit{}, nil, false, err
		}
		commit, err := decodeCommit(body, expectedSHA)
		if err != nil {
			return nil, nil, rawCommit{}, nil, false, queryError(ErrorInvalidResponse, err)
		}
		if page == 1 {
			firstHeader = headers
			metadata = commit
		}
		digestMaterial = append(digestMaterial, body...)
		digestMaterial = append(digestMaterial, '\n')
		if len(files)+len(commit.Files) > MaxChangedFileInventory {
			remaining := MaxChangedFileInventory - len(files)
			files = append(files, commit.Files[:remaining]...)
			truncated = true
			break
		}
		files = append(files, commit.Files...)
		if len(commit.Files) < 100 {
			break
		}
		if page == MaxChangedFileInventory/100 {
			truncated = true
		}
	}
	metadata.Files = files
	return digestMaterial, firstHeader, metadata, files, truncated, nil
}

func collectChangedFiles(ctx context.Context, filter *redact.Filter, rawFiles []rawChangedFile, maxFiles, maxPatchBytes int) ([]ChangedFile, []string, bool, error) {
	orderedFiles := append([]rawChangedFile(nil), rawFiles...)
	sort.Slice(orderedFiles, func(left, right int) bool { return orderedFiles[left].Filename < orderedFiles[right].Filename })
	rawFiles = orderedFiles
	truncated := len(rawFiles) > MaxChangedFileInventory
	if len(rawFiles) > MaxChangedFileInventory {
		rawFiles = rawFiles[:MaxChangedFileInventory]
	}
	files := make([]ChangedFile, 0, min(len(rawFiles), maxFiles))
	omitted := make([]string, 0)
	patchBytesRemaining := MaxTotalPatchBytes
	for _, raw := range rawFiles {
		filename, ok := validRepoPath(raw.Filename)
		if !ok || raw.Additions < 0 || raw.Deletions < 0 || raw.Changes < 0 {
			return nil, nil, false, errors.New("changed file metadata is invalid")
		}
		if len(files) == maxFiles {
			if len(omitted) < MaxChangedFileInventory {
				omitted = append(omitted, filename)
			}
			continue
		}
		file := ChangedFile{
			Filename: filename, Status: boundedStatus(raw.Status),
			Additions: raw.Additions, Deletions: raw.Deletions, Changes: raw.Changes,
		}
		if raw.Patch != "" {
			patchLimit := min(maxPatchBytes, patchBytesRemaining)
			if patchLimit == 0 {
				truncated = true
			} else {
				patch, err := filter.Untrusted(ctx, "github", raw.Patch, patchLimit)
				if err != nil {
					return nil, nil, false, err
				}
				file.Patch = &patch
				patchBytesRemaining -= len(patch.Content)
				if patch.Truncated {
					truncated = true
				}
			}
		}
		files = append(files, file)
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Filename < files[right].Filename })
	sort.Strings(omitted)
	return files, omitted, truncated || len(omitted) > 0, nil
}

func boundedStatus(status string) string {
	switch status {
	case "added", "removed", "modified", "renamed", "copied", "changed", "unchanged":
		return status
	default:
		return "unknown"
	}
}

func boundedPullRequestState(state string) string {
	switch state {
	case "open", "closed":
		return state
	default:
		return "unknown"
	}
}

type rawPullRequest struct {
	Number   int        `json:"number"`
	Title    string     `json:"title"`
	State    string     `json:"state"`
	HTMLURL  string     `json:"html_url"`
	MergedAt *time.Time `json:"merged_at"`
}

func (connector *Connector) fetchPullRequests(
	ctx context.Context,
	endpoint *url.URL,
	credential string,
	requestPath string,
) ([]PullRequest, bool, error) {
	body, _, err := connector.get(ctx, endpoint, credential, requestPath, defaultPullRequestMediaType)
	if err != nil {
		return nil, false, err
	}
	var raw []rawPullRequest
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, false, queryError(ErrorInvalidResponse, errors.New("pull request response is invalid"))
	}
	truncated := len(raw) > MaxPullRequests
	if len(raw) > MaxPullRequests {
		raw = raw[:MaxPullRequests]
	}
	result := make([]PullRequest, 0, len(raw))
	for _, item := range raw {
		if item.Number < 1 || item.Title == "" {
			continue
		}
		title, err := connector.filter.Untrusted(ctx, "github", item.Title, MaxCommitMessageBytes)
		if err != nil {
			return nil, false, queryError(ErrorInvalidResponse, err)
		}
		result = append(result, PullRequest{
			Number: item.Number, Title: title, State: boundedPullRequestState(item.State),
			MergedAt:  item.MergedAt,
			Reference: safeSourceReference(item.HTMLURL, endpoint, requestPath),
		})
	}
	return result, truncated, nil
}

func (connector *Connector) get(ctx context.Context, endpoint *url.URL, credential, requestURI, accept string) ([]byte, http.Header, error) {
	body, headers, _, err := connector.getLimited(ctx, endpoint, credential, requestURI, accept, MaxResponseBytes, false)
	return body, headers, err
}

func (connector *Connector) getTruncated(ctx context.Context, endpoint *url.URL, credential, requestURI, accept string, maxBytes int) ([]byte, http.Header, bool, error) {
	return connector.getLimited(ctx, endpoint, credential, requestURI, accept, maxBytes, true)
}

func (connector *Connector) getLimited(
	ctx context.Context,
	endpoint *url.URL,
	credential, requestURI, accept string,
	maxBytes int,
	allowTruncate bool,
) ([]byte, http.Header, bool, error) {
	requestTarget, err := url.ParseRequestURI(requestURI)
	if err != nil || requestTarget == nil {
		return nil, nil, false, queryError(ErrorInvalidQuery, err)
	}
	requestURL := (&url.URL{Scheme: endpoint.Scheme, Host: endpoint.Host, Path: requestTarget.Path, RawQuery: requestTarget.RawQuery}).String()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, nil, false, queryError(ErrorInvalidQuery, err)
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("X-GitHub-Api-Version", githubRESTVersion)
	request.Header.Set("User-Agent", "Relythra/1.0")
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	response, err := connector.client.Do(request)
	if err != nil {
		return nil, nil, false, classifyRequestError(err)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(maxBytes)+1))
	if readErr != nil {
		return nil, nil, false, classifyReadError(readErr)
	}
	if response.StatusCode == http.StatusUnauthorized {
		return nil, nil, false, queryError(ErrorPermissionDenied, ErrPermissionDenied)
	}
	if response.StatusCode == http.StatusForbidden {
		if response.Header.Get("Retry-After") != "" || response.Header.Get("X-RateLimit-Remaining") == "0" {
			return nil, nil, false, rateLimitError(response.Header)
		}
		return nil, nil, false, queryError(ErrorPermissionDenied, ErrPermissionDenied)
	}
	if response.StatusCode == http.StatusTooManyRequests {
		return nil, nil, false, rateLimitError(response.Header)
	}
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone {
		return nil, nil, false, queryError(ErrorRevisionUnavailable, ErrRevisionUnavailable)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, nil, false, queryError(ErrorRemoteUnavailable, fmt.Errorf("HTTP status %d", response.StatusCode))
	}
	truncated := len(body) > maxBytes
	if truncated && !allowTruncate {
		category := ErrorResponseTooLarge
		return nil, nil, false, queryError(category, ErrResponseTooLarge)
	}
	if truncated {
		body = body[:maxBytes]
	}
	return body, response.Header.Clone(), truncated, nil
}

func rateLimitError(headers http.Header) error {
	queryError := &QueryError{Category: ErrorRateLimited, Cause: ErrRateLimited}
	if seconds, err := strconv.Atoi(strings.TrimSpace(headers.Get("Retry-After"))); err == nil && seconds > 0 {
		queryError.RetryAfter = min(time.Duration(seconds)*time.Second, MaxRateLimitRetryAfter)
	}
	if epoch, err := strconv.ParseInt(headers.Get("X-RateLimit-Reset"), 10, 64); err == nil && epoch > 0 {
		queryError.RateLimitReset = time.Unix(epoch, 0).UTC()
	}
	return queryError
}

func validRepoPath(raw string) (string, bool) {
	if raw == "" || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\\") || strings.HasPrefix(raw, "/") ||
		strings.IndexFunc(raw, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 {
		return "", false
	}
	clean := path.Clean(raw)
	if clean != raw || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

func escapeRepoPath(raw string) string {
	parts := strings.Split(raw, "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.Join(parts, "/")
}

func isDependencyFile(filename string) bool {
	base := path.Base(filename)
	switch base {
	case "go.mod", "go.sum", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
		"requirements.txt", "pyproject.toml", "poetry.lock", "Cargo.toml", "Cargo.lock",
		"Gemfile", "Gemfile.lock", "composer.json", "composer.lock":
		return true
	default:
		return false
	}
}

func safeSourceReference(htmlURL string, endpoint *url.URL, fallback string) string {
	parsed, err := url.Parse(htmlURL)
	if err == nil && parsed != nil && parsed.Scheme == "https" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" {
		host := strings.ToLower(parsed.Hostname())
		apiHost := strings.ToLower(endpoint.Hostname())
		if host == apiHost || apiHost == "api.github.com" && host == "github.com" {
			return parsed.String()
		}
	}
	requestTarget, err := url.ParseRequestURI(fallback)
	if err != nil {
		requestTarget = &url.URL{Path: "/"}
	}
	return (&url.URL{Scheme: endpoint.Scheme, Host: endpoint.Host, Path: requestTarget.Path, RawQuery: requestTarget.RawQuery}).String()
}

func bodyDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func classifyRequestError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return queryError(ErrorTimeout, err)
	}
	if errors.Is(err, outbound.ErrRedirectBlocked) || errors.Is(err, outbound.ErrUnsafeAddress) ||
		errors.Is(err, outbound.ErrHostNotAllowed) || errors.Is(err, outbound.ErrPortNotAllowed) ||
		errors.Is(err, outbound.ErrSchemeNotAllowed) || errors.Is(err, outbound.ErrResolutionFailed) {
		return queryError(ErrorPolicyRejected, err)
	}
	return queryError(ErrorNetwork, err)
}

func classifyReadError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return queryError(ErrorTimeout, err)
	}
	return queryError(ErrorNetwork, err)
}

type timeoutError interface{ Timeout() bool }

func isTimeout(err error) bool {
	var timeout timeoutError
	return errors.As(err, &timeout) && timeout.Timeout()
}

func queryError(category ErrorCategory, cause error) error {
	return &QueryError{Category: category, Cause: cause}
}
