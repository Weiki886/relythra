package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/connector/github"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
)

func TestPersistGitHubEvidenceValidatesDeploymentOwnershipAndReplays(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	repository := NewPostgres(db)
	fixture := insertStoreFixture(t, ctx, db, "github-evidence-store")
	deploymentInput := fixture.deploymentInput("github-evidence-store-deployment")
	deploymentInput.SourceReference = "https://example.com/deployments/github-evidence-store"
	deployment, created, err := repository.CreateDeploymentEvent(ctx, deploymentInput)
	if err != nil || !created {
		t.Fatalf("create deployment: created=%v err=%v", created, err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO deployment_candidates (project_id, incident_id, deployment_event_id, match_status, match_reason)
		VALUES ($1, $2, $3, 'MATCHED', 'integration test candidate')
	`, fixture.projectID, fixture.incidentID, deployment.ID); err != nil {
		t.Fatalf("link deployment candidate: %v", err)
	}
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	meta := evidence.GitHubEvidenceContext{
		InvestigationID: fixture.investigationID,
		CollectedAt:     fixture.startedAt.Add(10 * time.Minute),
	}
	result := githubResultForDeployment(deployment.ID, fixture.commitSHA, fixture.startedAt.Add(time.Minute))

	first, wasCreated, err := repository.PersistGitHubEvidence(ctx, result, meta, filter)
	if err != nil || !wasCreated {
		t.Fatalf("persist GitHub Evidence: created=%v err=%v", wasCreated, err)
	}
	if first.SourceType != evidence.SourceGitHub || first.EntityType != "SERVICE" || first.EntityID == nil || *first.EntityID != fixture.serviceID {
		t.Fatalf("persisted GitHub Evidence association = %+v", first)
	}

	replayed, wasCreated, err := repository.PersistGitHubEvidence(ctx, result, meta, filter)
	if err != nil || wasCreated || replayed.ID != first.ID {
		t.Fatalf("replay = (%+v, created=%v, err=%v), want same immutable row", replayed, wasCreated, err)
	}
	timeline, err := repository.GetInvestigationTimeline(ctx, fixture.investigationID, InvestigationTimelineFilter{SourceType: string(evidence.SourceGitHub)}, 10, 0)
	if err != nil {
		t.Fatalf("read GitHub timeline: %v", err)
	}
	if timeline.Total != 1 || len(timeline.Items) != 1 || timeline.Items[0].Evidence.ID != first.ID {
		t.Fatalf("GitHub timeline = %+v, want one persisted observation", timeline)
	}
}

func TestPersistGitHubEvidenceRejectsUnownedUnlinkedAndMismatchedDeployment(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	repository := NewPostgres(db)
	fixture := insertStoreFixture(t, ctx, db, "github-evidence-validation")
	other := insertStoreFixture(t, ctx, db, "github-evidence-other-investigation")
	deploymentInput := fixture.deploymentInput("github-evidence-validation-deployment")
	deploymentInput.SourceReference = "https://example.com/deployments/github-evidence-validation"
	deployment, _, err := repository.CreateDeploymentEvent(ctx, deploymentInput)
	if err != nil {
		t.Fatalf("create deployment: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO deployment_candidates (project_id, incident_id, deployment_event_id, match_status, match_reason)
		VALUES ($1, $2, $3, 'MATCHED', 'integration test candidate')
	`, fixture.projectID, fixture.incidentID, deployment.ID); err != nil {
		t.Fatalf("link deployment candidate: %v", err)
	}
	unlinkedInput := fixture.deploymentInput("github-evidence-unlinked-deployment")
	unlinkedInput.SourceReference = "https://example.com/deployments/github-evidence-unlinked"
	unlinked, _, err := repository.CreateDeploymentEvent(ctx, unlinkedInput)
	if err != nil {
		t.Fatalf("create unlinked deployment: %v", err)
	}
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	meta := evidence.GitHubEvidenceContext{InvestigationID: other.investigationID, CollectedAt: fixture.startedAt.Add(10 * time.Minute)}
	result := githubResultForDeployment(deployment.ID, fixture.commitSHA, fixture.startedAt.Add(time.Minute))
	if _, _, err := repository.PersistGitHubEvidence(ctx, result, meta, filter); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-Investigation persistence error = %v, want ErrNotFound", err)
	}

	meta.InvestigationID = fixture.investigationID
	result.DeploymentEventID = unlinked.ID
	if _, _, err := repository.PersistGitHubEvidence(ctx, result, meta, filter); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unlinked deployment persistence error = %v, want ErrNotFound", err)
	}

	result = githubResultForDeployment(deployment.ID, strings.Repeat("b", 40), fixture.startedAt.Add(time.Minute))
	if _, _, err := repository.PersistGitHubEvidence(ctx, result, meta, filter); !errors.Is(err, ErrConflict) {
		t.Fatalf("Commit SHA mismatch error = %v, want ErrConflict", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM evidence WHERE source_type='GITHUB'`).Scan(&count); err != nil {
		t.Fatalf("count GitHub Evidence: %v", err)
	}
	if count != 0 {
		t.Fatalf("invalid associations persisted %d GitHub Evidence rows", count)
	}
}

func githubResultForDeployment(deploymentID, commitSHA string, authorDate time.Time) github.Result {
	text := func(content string) redact.UntrustedData {
		return redact.UntrustedData{Trust: "untrusted_data", Source: "github", Content: content, OriginalBytes: len(content)}
	}
	diff := text("diff --git a/main.go b/main.go")
	return github.Result{
		CommitSHA: commitSHA, DeploymentEventID: deploymentID,
		Message: text("diagnostic fix"), AuthorDate: authorDate,
		SourceReference: "https://github.com/example/service/commit/" + commitSHA,
		ResponseSHA256:  strings.Repeat("c", 64), DiffSHA256: strings.Repeat("d", 64),
		ChangedFiles:    []github.ChangedFile{},
		OmittedFiles:    []string{},
		PullRequests:    []github.PullRequest{{Number: 12, Title: text("diagnostic fix"), State: "closed", Reference: "https://github.com/example/service/pull/12"}},
		DependencyFiles: []github.DependencyFile{},
		Diff:            &diff,
		Warnings:        []string{},
	}
}
