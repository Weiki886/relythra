// Package datasource defines the validated configuration contract for the
// external systems that Relythra may query during diagnosis.
package datasource

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Weiki886/relythra/internal/security/secrets"
)

type SourceType string

const (
	SourceGitHub     SourceType = "GITHUB"
	SourceGrafana    SourceType = "GRAFANA"
	SourcePrometheus SourceType = "PROMETHEUS"
	SourceLoki       SourceType = "LOKI"
	SourceRuntime    SourceType = "RUNTIME"
)

func (source SourceType) Valid() bool {
	switch source {
	case SourceGitHub, SourceGrafana, SourcePrometheus, SourceLoki, SourceRuntime:
		return true
	default:
		return false
	}
}

type RuntimeType string

const (
	RuntimeDockerCompose RuntimeType = "docker-compose"
	RuntimeKubernetes    RuntimeType = "kubernetes"
)

func (runtime RuntimeType) Valid() bool {
	return runtime == RuntimeDockerCompose || runtime == RuntimeKubernetes
}

type ValidationIssue struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type PublicSettings struct {
	Endpoint          string                    `json:"endpoint"`
	Repository        string                    `json:"repository,omitempty"`
	RuntimeLabels     map[string]string         `json:"runtime_labels,omitempty"`
	ContainerMappings []RuntimeContainerMapping `json:"container_mappings,omitempty"`
}

// RuntimeContainerMapping explicitly assigns one observed cgroup identity to
// the service/environment scope of its versioned runtime data source mapping.
type RuntimeContainerMapping struct {
	HostID   string `json:"host_id"`
	CgroupID string `json:"cgroup_id"`
}

var (
	repositoryPattern = regexp.MustCompile(
		`^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$`,
	)
	runtimeMappingHostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	composeLabels             = []string{"project", "service", "env", "host_id", "container_id"}
)

func ValidateMapping(
	source SourceType,
	runtime RuntimeType,
	settings PublicSettings,
	templateIDs []string,
	secretReference *secrets.Reference,
) []ValidationIssue {
	issues := make([]ValidationIssue, 0)
	if !source.Valid() {
		issues = append(issues, issue("source_type", "unsupported", "source type is not supported"))
	}
	if source == SourceRuntime {
		if runtime == "" {
			issues = append(issues, issue("runtime_type", "required", "runtime type is required"))
		} else if !runtime.Valid() {
			issues = append(issues, issue("runtime_type", "unsupported", "runtime type is not supported"))
		} else {
			issues = append(issues, ValidateRuntimeLabels(runtime, settings.RuntimeLabels)...)
		}
		if runtime == RuntimeDockerCompose {
			issues = append(issues, ValidateRuntimeContainerMappings(settings.ContainerMappings)...)
		} else if len(settings.ContainerMappings) > 0 {
			issues = append(issues, issue("public_settings.container_mappings", "unsupported_runtime", "container mappings are only supported for Docker Compose in v1"))
		}
	} else {
		if runtime != "" {
			issues = append(issues, issue("runtime_type", "not_applicable", "runtime type only applies to runtime mappings"))
		}
		if len(settings.ContainerMappings) > 0 {
			issues = append(issues, issue("public_settings.container_mappings", "not_applicable", "container mappings only apply to runtime mappings"))
		}
	}

	issues = append(issues, validateEndpoint(settings.Endpoint)...)
	if source == SourceGitHub {
		repository := strings.TrimSpace(settings.Repository)
		switch {
		case repository == "":
			issues = append(issues, issue("public_settings.repository", "required", "GitHub repository is required"))
		case !repositoryPattern.MatchString(repository):
			issues = append(issues, issue("public_settings.repository", "invalid_format", "GitHub repository must use owner/name format"))
		}
	} else if strings.TrimSpace(settings.Repository) != "" {
		issues = append(issues, issue("public_settings.repository", "not_applicable", "repository only applies to GitHub mappings"))
	}

	if secretReference != nil {
		if _, err := secrets.ParseReference(secretReference.String()); err != nil {
			issues = append(issues, issue("secret_ref", "invalid_reference", "secret reference is invalid"))
		}
	}
	if len(templateIDs) == 0 {
		issues = append(issues, issue("template_ids", "required", "at least one query template is required"))
	} else {
		_, templateIssues := ResolveTemplates(source, templateIDs)
		issues = append(issues, templateIssues...)
	}
	return issues
}

func ValidateRuntimeContainerMappings(mappings []RuntimeContainerMapping) []ValidationIssue {
	if len(mappings) > 1000 {
		return []ValidationIssue{issue("public_settings.container_mappings", "too_many", "at most 1000 container mappings are allowed")}
	}
	issues := make([]ValidationIssue, 0)
	seen := make(map[string]struct{}, len(mappings))
	for index, mapping := range mappings {
		prefix := "public_settings.container_mappings[" + strconv.Itoa(index) + "]"
		if !runtimeMappingHostPattern.MatchString(mapping.HostID) {
			issues = append(issues, issue(prefix+".host_id", "invalid_identity", "host ID must use the supported identity format"))
		}
		if mapping.CgroupID == "" || len(mapping.CgroupID) > 4096 || strings.TrimSpace(mapping.CgroupID) != mapping.CgroupID || mapping.CgroupID == "/" || strings.ContainsAny(mapping.CgroupID, "\r\n\x00") {
			issues = append(issues, issue(prefix+".cgroup_id", "invalid_identity", "cgroup ID must be a non-root exact identity of at most 4096 bytes"))
		}
		key := mapping.HostID + "\x00" + mapping.CgroupID
		if _, exists := seen[key]; exists {
			issues = append(issues, issue(prefix, "duplicate_identity", "host and cgroup identity must be unique"))
		}
		seen[key] = struct{}{}
	}
	return issues
}

func ValidateRuntimeLabels(runtime RuntimeType, labels map[string]string) []ValidationIssue {
	switch runtime {
	case RuntimeDockerCompose:
		issues := make([]ValidationIssue, 0)
		allowed := make(map[string]struct{}, len(composeLabels))
		for _, label := range composeLabels {
			allowed[label] = struct{}{}
			if strings.TrimSpace(labels[label]) == "" {
				issues = append(issues, issue(
					"runtime_labels."+label,
					"required",
					"required Compose label is missing",
				))
			}
		}
		keys := make([]string, 0, len(labels))
		for key := range labels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if _, ok := allowed[key]; !ok {
				issues = append(issues, issue(
					"runtime_labels."+key,
					"unsupported_label",
					"label is not supported for Docker Compose",
				))
			}
		}
		return issues
	case RuntimeKubernetes:
		return []ValidationIssue{issue(
			"runtime_type",
			"unsupported_runtime",
			"Kubernetes runtime diagnosis is not supported in v1",
		)}
	default:
		return []ValidationIssue{issue(
			"runtime_type",
			"unsupported",
			"runtime type is not supported",
		)}
	}
}

func validateEndpoint(raw string) []ValidationIssue {
	endpoint := strings.TrimSpace(raw)
	if endpoint == "" {
		return []ValidationIssue{issue(
			"public_settings.endpoint",
			"required",
			"data source endpoint is required",
		)}
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" {
		return []ValidationIssue{issue(
			"public_settings.endpoint",
			"invalid_url",
			"data source endpoint is invalid",
		)}
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return []ValidationIssue{issue(
			"public_settings.endpoint",
			"unsupported_scheme",
			"data source endpoint must use HTTP or HTTPS",
		)}
	}
	if parsed.User != nil {
		return []ValidationIssue{issue(
			"public_settings.endpoint",
			"credentials_not_allowed",
			"data source endpoint must not contain credentials",
		)}
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.EscapedPath() != "" && parsed.EscapedPath() != "/") {
		return []ValidationIssue{issue(
			"public_settings.endpoint",
			"base_url_required",
			"data source endpoint must be a base URL without query, fragment, or path",
		)}
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return []ValidationIssue{issue(
				"public_settings.endpoint",
				"invalid_port",
				"data source endpoint port is invalid",
			)}
		}
	}
	host := parsed.Hostname()
	if strings.ContainsAny(host, " /\\@") || net.ParseIP(host) != nil && strings.Contains(host, "%") {
		return []ValidationIssue{issue(
			"public_settings.endpoint",
			"invalid_host",
			"data source endpoint host is invalid",
		)}
	}
	return nil
}

func issue(field, code, message string) ValidationIssue {
	return ValidationIssue{Field: field, Code: code, Message: message}
}
