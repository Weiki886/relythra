package datasource

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	QueryTypeRange   = "range"
	QueryTypeInstant = "instant"

	DefaultQueryLimit     = 20
	MaxQueryLimit         = 100
	DefaultQueryMaxSeries = 20
	MaxQueryMaxSeries     = 100
	DefaultQueryMaxPoints = 1000
	MaxQueryMaxPoints     = 20000
	MaxQueryTotalPoints   = 20000
	MaxQueryWindow        = 6 * time.Hour
	MaxLokiQueryWindow    = 2 * time.Hour
	DefaultQueryStep      = 30 * time.Second
	MinQueryStep          = 5 * time.Second
	MaxQueryStep          = 5 * time.Minute
)

type Template struct {
	ID                string
	Version           int
	Source            SourceType
	Purpose           string
	ResultSchema      string
	AllowedParameters []string
}

type QueryParameters struct {
	Service     string
	Environment string
	Direction   string
	Severity    string
	QueryType   string
	At          string
	Start       string
	End         string
	Step        string
	Limit       int
	Cursor      string
	MaxSeries   int
	MaxPoints   int
	Extra       map[string]any
}

type NormalizedQuery struct {
	TemplateID  string
	Version     int
	Service     string
	Environment string
	Direction   string
	Severity    string
	QueryType   string
	Start       time.Time
	End         time.Time
	Step        time.Duration
	Limit       int
	Cursor      string
	MaxSeries   int
	MaxPoints   int
}

var commonParameters = []string{
	"cursor",
	"end",
	"limit",
	"max_series",
	"service",
	"start",
}

var prometheusParameters = []string{
	"at", "end", "environment", "max_points", "max_series", "query_type", "service", "start", "step",
}

var lokiParameters = []string{
	"cursor", "direction", "end", "environment", "limit", "service", "severity", "start",
}

var templateRegistry = map[string]Template{
	"github.commits.v1": {
		ID: "github.commits.v1", Version: 1, Source: SourceGitHub,
		Purpose:      "Read commits in the bounded diagnosis window.",
		ResultSchema: "code.commit_list.v1", AllowedParameters: commonParameters,
	},
	"github.pull_requests.v1": {
		ID: "github.pull_requests.v1", Version: 1, Source: SourceGitHub,
		Purpose:      "Read pull requests associated with release commits.",
		ResultSchema: "code.pull_request_list.v1", AllowedParameters: commonParameters,
	},
	"github.diff.v1": {
		ID: "github.diff.v1", Version: 1, Source: SourceGitHub,
		Purpose:      "Read a bounded pull request or commit diff.",
		ResultSchema: "code.diff.v1", AllowedParameters: commonParameters,
	},
	"grafana.alert.v1": {
		ID: "grafana.alert.v1", Version: 1, Source: SourceGrafana,
		Purpose:      "Read the alert definition associated with a fingerprint.",
		ResultSchema: "alert.grafana.v1", AllowedParameters: commonParameters,
	},
	"grafana.health.v1": {
		ID: "grafana.health.v1", Version: 1, Source: SourceGrafana,
		Purpose:      "Read datasource health and version metadata.",
		ResultSchema: "source.health.v1", AllowedParameters: commonParameters,
	},
	"prometheus.service.latency.v1": {
		ID: "prometheus.service.latency.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read bounded service P95 request latency series.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.service.error_ratio.v1": {
		ID: "prometheus.service.error_ratio.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read bounded service HTTP error ratio series.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.service.request_rate.v1": {
		ID: "prometheus.service.request_rate.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read bounded service request rate series.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.container.memory.v1": {
		ID: "prometheus.container.memory.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read bounded container memory series.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.container.cpu.v1": {
		ID: "prometheus.container.cpu.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read bounded container CPU usage series.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.database.query_latency.v1": {
		ID: "prometheus.database.query_latency.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read bounded database query latency series.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.node.capacity.v1": {
		ID: "prometheus.node.capacity.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read bounded host capacity series.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.runtime.container.cpu.v1": {
		ID: "prometheus.runtime.container.cpu.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read per-cgroup CPU usage with host and mapping metadata.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.runtime.container.memory.v1": {
		ID: "prometheus.runtime.container.memory.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read per-cgroup memory working set with host and mapping metadata.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.runtime.container.oom_events.v1": {
		ID: "prometheus.runtime.container.oom_events.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read per-cgroup OOM counter changes with host and mapping metadata.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.runtime.container.start_time.v1": {
		ID: "prometheus.runtime.container.start_time.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read per-cgroup start time with host and mapping metadata.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.runtime.host.cpu.v1": {
		ID: "prometheus.runtime.host.cpu.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read host CPU usage by host and scrape instance.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.runtime.host.memory_available.v1": {
		ID: "prometheus.runtime.host.memory_available.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read host available memory by scrape instance.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"prometheus.runtime.host.load.v1": {
		ID: "prometheus.runtime.host.load.v1", Version: 1, Source: SourcePrometheus,
		Purpose:      "Read host one-minute load average by scrape instance.",
		ResultSchema: "metric.series.v1", AllowedParameters: prometheusParameters,
	},
	"loki.service.errors.v1": {
		ID: "loki.service.errors.v1", Version: 1, Source: SourceLoki,
		Purpose:      "Read bounded error log entries.",
		ResultSchema: "log.entry_list.v1", AllowedParameters: lokiParameters,
	},
	"loki.service.slow_queries.v1": {
		ID: "loki.service.slow_queries.v1", Version: 1, Source: SourceLoki,
		Purpose:      "Read bounded slow database query log entries.",
		ResultSchema: "log.entry_list.v1", AllowedParameters: lokiParameters,
	},
	"loki.container.restarts.v1": {
		ID: "loki.container.restarts.v1", Version: 1, Source: SourceLoki,
		Purpose:      "Read bounded container restart log entries.",
		ResultSchema: "log.entry_list.v1", AllowedParameters: lokiParameters,
	},
	"loki.service.config_errors.v1": {
		ID: "loki.service.config_errors.v1", Version: 1, Source: SourceLoki,
		Purpose:      "Read bounded service configuration error log entries.",
		ResultSchema: "log.entry_list.v1", AllowedParameters: lokiParameters,
	},
	"runtime.containers.v1": {
		ID: "runtime.containers.v1", Version: 1, Source: SourceRuntime,
		Purpose:      "Read Docker container state through fixed metrics.",
		ResultSchema: "runtime.container_list.v1", AllowedParameters: commonParameters,
	},
	"runtime.host.v1": {
		ID: "runtime.host.v1", Version: 1, Source: SourceRuntime,
		Purpose:      "Read host capacity metrics.",
		ResultSchema: "runtime.host_state.v1", AllowedParameters: commonParameters,
	},
	"runtime.events.v1": {
		ID: "runtime.events.v1", Version: 1, Source: SourceRuntime,
		Purpose:      "Read bounded container lifecycle events.",
		ResultSchema: "runtime.event_list.v1", AllowedParameters: commonParameters,
	},
}

var servicePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func ResolveTemplates(source SourceType, templateIDs []string) ([]Template, []ValidationIssue) {
	templates := make([]Template, 0, len(templateIDs))
	issues := make([]ValidationIssue, 0)
	seen := make(map[string]struct{}, len(templateIDs))
	for _, rawID := range templateIDs {
		id := strings.TrimSpace(rawID)
		template, ok := templateRegistry[id]
		if !ok || template.Source != source {
			issues = append(issues, issue(
				"template_ids",
				"unsupported_template",
				fmt.Sprintf("query template %q is not available for this source", id),
			))
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			issues = append(issues, issue(
				"template_ids",
				"duplicate_template",
				fmt.Sprintf("query template %q is duplicated", id),
			))
			continue
		}
		seen[id] = struct{}{}
		templates = append(templates, template)
	}
	return templates, issues
}

func ValidateQuery(template Template, parameters QueryParameters) (NormalizedQuery, []ValidationIssue) {
	issues := make([]ValidationIssue, 0)
	allowed := make(map[string]struct{}, len(template.AllowedParameters))
	for _, parameter := range template.AllowedParameters {
		allowed[parameter] = struct{}{}
	}
	extraKeys := make([]string, 0, len(parameters.Extra))
	for key := range parameters.Extra {
		extraKeys = append(extraKeys, key)
	}
	sort.Strings(extraKeys)
	for _, key := range extraKeys {
		if _, ok := allowed[key]; !ok {
			issues = append(issues, issue(
				"parameters."+key,
				"unsupported_parameter",
				"query parameter is not allowed by the fixed template",
			))
		}
	}

	service := strings.TrimSpace(parameters.Service)
	if !servicePattern.MatchString(service) {
		issues = append(issues, issue(
			"parameters.service",
			"invalid_format",
			"service must be a lowercase service slug",
		))
	}
	environment := strings.TrimSpace(parameters.Environment)
	queryType := ""
	var start, end time.Time
	var startOK, endOK bool
	direction := ""
	severity := strings.ToLower(strings.TrimSpace(parameters.Severity))
	if template.Source == SourcePrometheus {
		if !servicePattern.MatchString(environment) {
			issues = append(issues, issue("parameters.environment", "required", "environment must be a lowercase environment slug"))
		}
		queryType = strings.TrimSpace(parameters.QueryType)
		if queryType == "" {
			queryType = QueryTypeRange
		}
		switch queryType {
		case QueryTypeRange:
			if strings.TrimSpace(parameters.At) != "" {
				issues = append(issues, issue("parameters.at", "unsupported_parameter", "at is only allowed for instant queries"))
			}
			start, startOK = parseQueryTime(parameters.Start, "parameters.start", &issues)
			end, endOK = parseQueryTime(parameters.End, "parameters.end", &issues)
		case QueryTypeInstant:
			if strings.TrimSpace(parameters.Start) != "" {
				issues = append(issues, issue("parameters.start", "unsupported_parameter", "start is not allowed for instant queries"))
			}
			if strings.TrimSpace(parameters.End) != "" {
				issues = append(issues, issue("parameters.end", "unsupported_parameter", "end is not allowed for instant queries"))
			}
			start, startOK = parseQueryTime(parameters.At, "parameters.at", &issues)
			end, endOK = start, startOK
		default:
			issues = append(issues, issue("parameters.query_type", "unsupported_value", "query_type must be range or instant"))
		}
	} else {
		start, startOK = parseQueryTime(parameters.Start, "parameters.start", &issues)
		end, endOK = parseQueryTime(parameters.End, "parameters.end", &issues)
		if template.Source == SourceLoki {
			if !servicePattern.MatchString(environment) {
				issues = append(issues, issue("parameters.environment", "required", "environment must be a lowercase environment slug"))
			}
			direction = strings.ToLower(strings.TrimSpace(parameters.Direction))
			if direction == "" {
				direction = "backward"
			}
			if direction != "backward" && direction != "forward" {
				issues = append(issues, issue("parameters.direction", "unsupported_value", "direction must be backward or forward"))
			}
			if severity != "" && severity != "debug" && severity != "info" && severity != "warn" && severity != "error" {
				issues = append(issues, issue("parameters.severity", "unsupported_value", "severity must be debug, info, warn, or error"))
			}
		} else if severity != "" || strings.TrimSpace(parameters.Direction) != "" {
			issues = append(issues, issue("parameters", "unsupported_parameter", "direction and severity are only allowed for Loki templates"))
		}
	}
	if startOK && endOK {
		if template.Source != SourcePrometheus || queryType == QueryTypeRange {
			maxWindow := MaxQueryWindow
			if template.Source == SourceLoki {
				maxWindow = MaxLokiQueryWindow
			}
			switch {
			case !end.After(start):
				issues = append(issues, issue(
					"parameters.end",
					"invalid_range",
					"query end must be after query start",
				))
			case end.Sub(start) > maxWindow:
				issues = append(issues, issue(
					"parameters.end",
					"window_too_large",
					"query window exceeds the fixed maximum",
				))
			}
		}
	}

	limit := parameters.Limit
	if limit == 0 {
		limit = DefaultQueryLimit
	}
	if limit < 1 || limit > MaxQueryLimit {
		issues = append(issues, issue(
			"parameters.limit",
			"out_of_range",
			"query limit is outside the allowed range",
		))
	}
	maxSeries := parameters.MaxSeries
	if maxSeries == 0 {
		maxSeries = MaxQueryMaxSeries
		if template.Source == SourcePrometheus {
			maxSeries = DefaultQueryMaxSeries
		}
	}
	if maxSeries < 1 || maxSeries > MaxQueryMaxSeries {
		issues = append(issues, issue(
			"parameters.max_series",
			"out_of_range",
			"maximum series count is outside the allowed range",
		))
	}
	maxPoints := parameters.MaxPoints
	step := time.Duration(0)
	if template.Source == SourcePrometheus {
		if queryType == QueryTypeInstant {
			maxPoints = 1
			if strings.TrimSpace(parameters.Step) != "" {
				issues = append(issues, issue("parameters.step", "unsupported_parameter", "step is only allowed for range queries"))
			}
			if parameters.MaxPoints != 0 && parameters.MaxPoints != 1 {
				issues = append(issues, issue("parameters.max_points", "out_of_range", "instant queries return exactly one point per series"))
			}
		} else {
			step = DefaultQueryStep
			if parameters.Step != "" {
				parsed, err := time.ParseDuration(strings.TrimSpace(parameters.Step))
				if err != nil || parsed < MinQueryStep || parsed > MaxQueryStep || parsed%time.Second != 0 {
					issues = append(issues, issue("parameters.step", "out_of_range", "step must be a whole-second duration from 5s through 5m"))
				} else {
					step = parsed
				}
			}
			if maxPoints == 0 {
				maxPoints = DefaultQueryMaxPoints
			}
			if maxPoints < 2 || maxPoints > MaxQueryMaxPoints {
				issues = append(issues, issue("parameters.max_points", "out_of_range", "maximum points must be between 2 and the global limit"))
			} else if startOK && endOK && end.After(start) && int(end.Sub(start)/step)+1 > maxPoints {
				issues = append(issues, issue("parameters.max_points", "insufficient_budget", "time range and step exceed the requested per-series point budget"))
			}
		}
		if maxSeries > 0 && maxPoints > 0 && maxSeries*maxPoints > MaxQueryTotalPoints {
			issues = append(issues, issue("parameters.max_points", "total_sample_budget_exceeded", "series and point budgets exceed the total sample limit"))
		}
	}
	cursor := strings.TrimSpace(parameters.Cursor)
	if len(cursor) > 512 || strings.ContainsAny(cursor, "\x00\r\n") {
		issues = append(issues, issue(
			"parameters.cursor",
			"invalid_format",
			"query cursor is invalid",
		))
	}

	return NormalizedQuery{
		TemplateID: template.ID, Version: template.Version,
		Service: service, Environment: environment, Direction: direction, Severity: severity, QueryType: queryType,
		Start: start.UTC(), End: end.UTC(), Step: step,
		Limit: limit, Cursor: cursor, MaxSeries: maxSeries, MaxPoints: maxPoints,
	}, issues
}

func parseQueryTime(raw, field string, issues *[]ValidationIssue) (time.Time, bool) {
	if strings.TrimSpace(raw) == "" {
		*issues = append(*issues, issue(field, "required", "query time is required"))
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		*issues = append(*issues, issue(field, "invalid_format", "query time must use RFC3339"))
		return time.Time{}, false
	}
	return parsed, true
}
