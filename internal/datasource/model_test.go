package datasource

import (
	"testing"

	"github.com/Weiki886/relythra/internal/security/secrets"
)

func TestValidateRuntimeLabelsReportsEachMissingComposeLabel(t *testing.T) {
	issues := ValidateRuntimeLabels(RuntimeDockerCompose, map[string]string{
		"project": "relythra",
	})
	for _, field := range []string{
		"runtime_labels.service",
		"runtime_labels.env",
		"runtime_labels.host_id",
		"runtime_labels.container_id",
	} {
		if !hasIssue(issues, field, "required") {
			t.Errorf("missing %s required issue: %#v", field, issues)
		}
	}
}

func TestValidateRuntimeLabelsRejectsBlankComposeLabel(t *testing.T) {
	issues := ValidateRuntimeLabels(RuntimeDockerCompose, map[string]string{
		"project":      "relythra",
		"service":      "checkout-api",
		"env":          "prod",
		"host_id":      "docker-host-1",
		"container_id": " ",
	})
	if !hasIssue(issues, "runtime_labels.container_id", "required") {
		t.Fatalf("issues = %#v", issues)
	}
}

func TestValidateRuntimeLabelsMarksKubernetesUnsupported(t *testing.T) {
	issues := ValidateRuntimeLabels(RuntimeKubernetes, map[string]string{})
	if !hasIssue(issues, "runtime_type", "unsupported_runtime") {
		t.Fatalf("issues = %#v", issues)
	}
	issues = ValidateMapping(SourceRuntime, RuntimeKubernetes, PublicSettings{
		Endpoint:          "https://cadvisor.example.test",
		ContainerMappings: []RuntimeContainerMapping{{HostID: "host-a", CgroupID: "cgroup-a"}},
	}, []string{"runtime.containers.v1"}, nil)
	if !hasIssue(issues, "public_settings.container_mappings", "unsupported_runtime") {
		t.Fatalf("Kubernetes container mapping issues = %#v", issues)
	}
}

func TestValidateRuntimeContainerMappingsRequiresUniqueHostAndCgroupIdentity(t *testing.T) {
	settings := PublicSettings{
		Endpoint: "https://prometheus.example.test",
		RuntimeLabels: map[string]string{
			"project": "relythra", "service": "checkout", "env": "demo",
			"host_id": "host-a", "container_id": "container-id",
		},
		ContainerMappings: []RuntimeContainerMapping{
			{HostID: "host-a", CgroupID: "cgroup-a"},
			{HostID: "host-a", CgroupID: "cgroup-a"},
		},
	}
	issues := ValidateMapping(SourceRuntime, RuntimeDockerCompose, settings, []string{"runtime.containers.v1"}, nil)
	if !hasIssue(issues, "public_settings.container_mappings[1]", "duplicate_identity") {
		t.Fatalf("duplicate mapping issues = %#v", issues)
	}

	settings.ContainerMappings = []RuntimeContainerMapping{{HostID: "host-a", CgroupID: "/"}}
	issues = ValidateMapping(SourceRuntime, RuntimeDockerCompose, settings, []string{"runtime.containers.v1"}, nil)
	if !hasIssue(issues, "public_settings.container_mappings[0].cgroup_id", "invalid_identity") {
		t.Fatalf("invalid cgroup issues = %#v", issues)
	}

	issues = ValidateMapping(SourcePrometheus, "", PublicSettings{
		Endpoint:          "https://prometheus.example.test",
		ContainerMappings: []RuntimeContainerMapping{{HostID: "host-a", CgroupID: "cgroup-a"}},
	}, []string{"prometheus.service.latency.v1"}, nil)
	if !hasIssue(issues, "public_settings.container_mappings", "not_applicable") {
		t.Fatalf("non-runtime mapping issues = %#v", issues)
	}
}

func TestValidateMappingRequiresGitHubRepository(t *testing.T) {
	reference := mustSecretReference(t, "env:GITHUB_TOKEN")
	issues := ValidateMapping(
		SourceGitHub,
		"",
		PublicSettings{Endpoint: "https://api.github.com"},
		[]string{"github.commits.v1"},
		&reference,
	)
	if !hasIssue(issues, "public_settings.repository", "required") {
		t.Fatalf("issues = %#v", issues)
	}
}

func TestValidateMappingRejectsEndpointWithCredentials(t *testing.T) {
	issues := ValidateMapping(
		SourcePrometheus,
		"",
		PublicSettings{Endpoint: "https://admin:secret@metrics.example.com"},
		[]string{"prometheus.service.latency.v1"},
		nil,
	)
	if !hasIssue(issues, "public_settings.endpoint", "credentials_not_allowed") {
		t.Fatalf("issues = %#v", issues)
	}
}

func TestValidateMappingRejectsRuntimeTypeForNonRuntimeSource(t *testing.T) {
	issues := ValidateMapping(
		SourcePrometheus,
		RuntimeDockerCompose,
		PublicSettings{Endpoint: "https://metrics.example.com"},
		[]string{"prometheus.service.latency.v1"},
		nil,
	)
	if !hasIssue(issues, "runtime_type", "not_applicable") {
		t.Fatalf("issues = %#v", issues)
	}
}

func mustSecretReference(t *testing.T, raw string) secrets.Reference {
	t.Helper()
	reference, err := secrets.ParseReference(raw)
	if err != nil {
		t.Fatalf("parse secret reference: %v", err)
	}
	return reference
}

func hasIssue(issues []ValidationIssue, field, code string) bool {
	for _, issue := range issues {
		if issue.Field == field && issue.Code == code {
			return true
		}
	}
	return false
}
