package prometheus

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/security/outbound"
	"github.com/Weiki886/relythra/internal/security/secrets"
)

const prometheusResponse = `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"service":"checkout-api","env":"prod"},"values":[[1793772240,"1.25"],[1793772300,"2.5"]]}]}}`

func TestQueryUsesFixedTemplateAndBoundedReadonlyRequest(t *testing.T) {
	const canary = "prometheus-query-secret-canary"
	reference, err := secrets.ParseReference("env:PROMETHEUS_QUERY_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/query_range" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+canary {
			t.Error("missing Bearer credential")
		}
		if request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("content type = %q", request.Header.Get("Content-Type"))
		}
		if err := request.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		query := request.Form.Get("query")
		if !strings.Contains(query, `demo_http_request_duration_seconds_bucket{service="checkout-api",env="prod"}`) {
			t.Errorf("query is not the registered fixed template: %s", query)
		}
		if strings.Contains(query, canary) || request.URL.RawQuery != "" {
			t.Error("credential or query leaked into URL")
		}
		if request.Form.Get("step") != "30s" {
			t.Errorf("step = %q", request.Form.Get("step"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, prometheusResponse)
	}))
	defer server.Close()

	connector := newTestConnector(t, server, func(_ context.Context, got secrets.Reference) (secrets.Secret, error) {
		if got.String() != reference.String() {
			t.Fatalf("secret reference = %q", got.String())
		}
		return secrets.New(canary)
	})
	query := validQuery("prometheus.service.latency.v1")
	result, err := connector.Query(context.Background(), Target{Endpoint: server.URL, SecretReference: &reference}, query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if result.TemplateID != query.TemplateID || result.TemplateVersion != 1 || result.Unit != "seconds" || result.Partial || result.Empty || result.Stale {
		t.Fatalf("result metadata = %+v", result)
	}
	if len(result.Series) != 1 || len(result.Series[0].Samples) != 2 || result.Series[0].Samples[1].Value != 2.5 {
		t.Fatalf("series = %+v", result.Series)
	}
	if result.ResponseSHA256 == "" || result.Duration < 0 || result.Query == "" || strings.Contains(fmt.Sprintf("%#v", result), canary) {
		t.Fatalf("unsafe/incomplete query metadata = %+v", result)
	}
}

func TestQuerySupportsOnlyRegisteredPrometheusTemplates(t *testing.T) {
	server, called := newCountingServer(t, prometheusResponse)
	connector := newTestConnector(t, server, nil)
	if _, err := connector.Query(context.Background(), Target{Endpoint: server.URL}, validQuery("prometheus.service.latency.v1")); err != nil {
		t.Fatalf("known template: %v", err)
	}
	if *called != 1 {
		t.Fatalf("request count = %d", *called)
	}
	unknown := validQuery("prometheus.user.query.v1")
	if _, err := connector.Query(context.Background(), Target{Endpoint: server.URL}, unknown); err == nil {
		t.Fatal("unknown template was executed")
	}
	if *called != 1 {
		t.Fatalf("unknown template reached Prometheus; requests=%d", *called)
	}
}

func TestRegisteredTemplatesBuildExpectedPromQLAndUnits(t *testing.T) {
	tests := []struct {
		templateID string
		query      string
		unit       string
	}{
		{
			templateID: "prometheus.service.latency.v1",
			query:      `histogram_quantile(0.95, sum by (le, route) (rate(demo_http_request_duration_seconds_bucket{service="checkout-api",env="prod"}[5m])))`,
			unit:       "seconds",
		},
		{
			templateID: "prometheus.service.error_ratio.v1",
			query:      `sum by (route) (rate(demo_http_requests_total{service="checkout-api",env="prod",status=~"5.."}[5m])) / clamp_min(sum by (route) (rate(demo_http_requests_total{service="checkout-api",env="prod"}[5m])), 1e-12)`,
			unit:       "ratio",
		},
		{
			templateID: "prometheus.service.request_rate.v1",
			query:      `sum by (route) (rate(demo_http_requests_total{service="checkout-api",env="prod"}[5m]))`,
			unit:       "requests_per_second",
		},
		{
			templateID: "prometheus.container.cpu.v1",
			query:      `sum by (container) (rate(container_cpu_usage_seconds_total{service="checkout-api",env="prod"}[5m]))`,
			unit:       "cores",
		},
		{
			templateID: "prometheus.container.memory.v1",
			query:      `sum by (container) (container_memory_working_set_bytes{service="checkout-api",env="prod"})`,
			unit:       "bytes",
		},
		{
			templateID: "prometheus.database.query_latency.v1",
			query:      `histogram_quantile(0.95, sum by (le, operation) (rate(db_client_query_duration_seconds_bucket{service="checkout-api",env="prod"}[5m])))`,
			unit:       "seconds",
		},
		{
			templateID: "prometheus.node.capacity.v1",
			query:      `node_memory_MemAvailable_bytes{service="checkout-api",env="prod"}`,
			unit:       "bytes",
		},
		{
			templateID: "prometheus.runtime.container.cpu.v1",
			query:      `sum by (id, host_id, mapping_status, container_label_com_docker_compose_service) (rate(container_cpu_usage_seconds_total{service="checkout-api",env="prod"}[5m]))`,
			unit:       "cores",
		},
		{
			templateID: "prometheus.runtime.container.memory.v1",
			query:      `sum by (id, host_id, mapping_status, container_label_com_docker_compose_service) (container_memory_working_set_bytes{service="checkout-api",env="prod"})`,
			unit:       "bytes",
		},
		{
			templateID: "prometheus.runtime.container.oom_events.v1",
			query:      `sum by (id, host_id, mapping_status, container_label_com_docker_compose_service) (increase(container_oom_events_total{service="checkout-api",env="prod"}[5m]))`,
			unit:       "events",
		},
		{
			templateID: "prometheus.runtime.container.start_time.v1",
			query:      `max by (id, host_id, mapping_status, container_label_com_docker_compose_service) (container_start_time_seconds{service="checkout-api",env="prod"})`,
			unit:       "unix_seconds",
		},
		{
			templateID: "prometheus.runtime.host.cpu.v1",
			query:      `sum by (host_id, instance) (rate(node_cpu_seconds_total{service="checkout-api",env="prod",mode!="idle"}[5m]))`,
			unit:       "cores",
		},
		{
			templateID: "prometheus.runtime.host.memory_available.v1",
			query:      `max by (host_id, instance) (node_memory_MemAvailable_bytes{service="checkout-api",env="prod"})`,
			unit:       "bytes",
		},
		{
			templateID: "prometheus.runtime.host.load.v1",
			query:      `max by (host_id, instance) (node_load1{service="checkout-api",env="prod"})`,
			unit:       "load_average",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.templateID, func(t *testing.T) {
			query, unit, err := buildExpression(validQuery(testCase.templateID))
			if err != nil {
				t.Fatalf("buildExpression: %v", err)
			}
			if query != testCase.query || unit != testCase.unit {
				t.Fatalf("expression = %q (%s), want %q (%s)", query, unit, testCase.query, testCase.unit)
			}
		})
	}
}

func TestInstantQueryUsesFixedTemplateAndParsesVectorResponse(t *testing.T) {
	const instant = `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"service":"checkout-api","env":"prod","route":"/orders"},"value":[1793772300,"12.5"]}]}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/query" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if err := request.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if request.Form.Get("time") != "1793772300.000" || request.Form.Has("start") || request.Form.Has("end") || request.Form.Has("step") {
			t.Errorf("instant parameters = %#v", request.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, instant)
	}))
	defer server.Close()

	query := validQuery("prometheus.service.request_rate.v1")
	query.QueryType = datasource.QueryTypeInstant
	query.Start = query.End
	query.Step, query.MaxPoints = 0, 1
	result, err := newTestConnector(t, server, nil).Query(context.Background(), Target{Endpoint: server.URL}, query)
	if err != nil {
		t.Fatalf("instant Query: %v", err)
	}
	if result.QueryType != datasource.QueryTypeInstant || len(result.Series) != 1 || len(result.Series[0].Samples) != 1 || result.Series[0].Samples[0].Value != 12.5 || !result.Series[0].Samples[0].Timestamp.Equal(query.End) {
		t.Fatalf("instant result = %+v", result)
	}
}

func TestQueryMarksWarningsAndMalformedSeriesPartialWhileKeepingValidSeries(t *testing.T) {
	body := `{"status":"success","warnings":["partial response"],"data":{"resultType":"matrix","result":[{"metric":{"service":"checkout-api","env":"prod"},"values":[[1793772000,"1"]]},{"metric":{"service":"bad"},"values":[["bad","NaN"]]}]}}`
	server, _ := newCountingServer(t, body)
	result, err := newTestConnector(t, server, nil).Query(context.Background(), Target{Endpoint: server.URL}, validQuery("prometheus.service.request_rate.v1"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !result.Partial || len(result.Series) != 1 || len(result.Warnings) < 2 {
		t.Fatalf("partial result = %+v", result)
	}
}

func TestQueryReportsEmptyAsMissingAndMarksStaleSamples(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		server, _ := newCountingServer(t, `{"status":"success","data":{"resultType":"matrix","result":[]}}`)
		result, err := newTestConnector(t, server, nil).Query(context.Background(), Target{Endpoint: server.URL}, validQuery("prometheus.service.request_rate.v1"))
		if err != nil {
			t.Fatal(err)
		}
		if !result.Empty || result.Stale || result.Partial {
			t.Fatalf("empty result semantics = %+v", result)
		}
	})

	t.Run("stale", func(t *testing.T) {
		server, _ := newCountingServer(t, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"service":"checkout-api","env":"prod"},"values":[[1793772000,"1"]]}]}}`)
		query := validQuery("prometheus.service.request_rate.v1")
		query.End = time.Unix(1793772300, 0).UTC()
		result, err := newTestConnector(t, server, nil).Query(context.Background(), Target{Endpoint: server.URL}, query)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Stale {
			t.Fatalf("stale sample was not marked: %+v", result)
		}
	})
}

func TestQueryRejectsResponseOverBudgetAndHTTPThrottle(t *testing.T) {
	t.Run("too many series", func(t *testing.T) {
		server, _ := newCountingServer(t, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"service":"checkout-api","env":"prod"},"values":[[1793772000,"1"]]},{"metric":{"service":"checkout-api","env":"prod","route":"/extra"},"values":[[1793772000,"1"]]}]}}`)
		query := validQuery("prometheus.service.request_rate.v1")
		query.MaxSeries = 1
		result, err := newTestConnector(t, server, nil).Query(context.Background(), Target{Endpoint: server.URL}, query)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Series) != 1 || !result.Partial {
			t.Fatalf("series limit result = %+v", result)
		}
	})

	t.Run("rate limit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()
		_, err := newTestConnector(t, server, nil).Query(context.Background(), Target{Endpoint: server.URL}, validQuery("prometheus.service.request_rate.v1"))
		if !IsErrorCategory(err, ErrorRateLimited) {
			t.Fatalf("error = %v, want rate limited", err)
		}
	})

	t.Run("too many points in one series", func(t *testing.T) {
		body := `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"service":"checkout-api","env":"prod"},"values":[[1793772000,"1"],[1793772030,"2"],[1793772060,"3"]]}]}}`
		server, _ := newCountingServer(t, body)
		query := validQuery("prometheus.service.request_rate.v1")
		query.End = query.Start.Add(30 * time.Second)
		query.MaxPoints = 2
		result, err := newTestConnector(t, server, nil).Query(context.Background(), Target{Endpoint: server.URL}, query)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(result.Series) != 1 || len(result.Series[0].Samples) != 2 || !result.Partial {
			t.Fatalf("point limit result = %+v", result)
		}
	})

	t.Run("response byte limit", func(t *testing.T) {
		server, _ := newCountingServer(t, strings.Repeat("x", MaxResponseBytes+1))
		_, err := newTestConnector(t, server, nil).Query(context.Background(), Target{Endpoint: server.URL}, validQuery("prometheus.service.request_rate.v1"))
		if !IsErrorCategory(err, ErrorResponseTooLarge) {
			t.Fatalf("error = %v, want response too large", err)
		}
	})
}

func TestQueryRejectsInsufficientBudgetBeforeNetwork(t *testing.T) {
	server, called := newCountingServer(t, prometheusResponse)
	query := validQuery("prometheus.service.latency.v1")
	query.MaxSeries, query.MaxPoints = 100, datasource.MaxQueryMaxPoints
	_, err := newTestConnector(t, server, nil).Query(context.Background(), Target{Endpoint: server.URL}, query)
	if !IsErrorCategory(err, ErrorInvalidQuery) {
		t.Fatalf("error = %v, want invalid query", err)
	}
	if *called != 0 {
		t.Fatalf("invalid budget performed %d requests", *called)
	}
}

func TestQueryClassifiesResponseBodyTimeout(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       errorReadCloser{err: testTimeoutError{}},
			Header:     make(http.Header),
		}, nil
	})}
	connector := &Connector{
		policy:   allowTestTargetPolicy{},
		resolver: resolverFunc(nil),
		client:   client,
	}
	_, err := connector.Query(context.Background(), Target{Endpoint: "https://metrics.example.test"}, validQuery("prometheus.service.request_rate.v1"))
	if !IsErrorCategory(err, ErrorTimeout) {
		t.Fatalf("error = %v, want timeout", err)
	}
}

func newTestConnector(t *testing.T, server *httptest.Server, resolve func(context.Context, secrets.Reference) (secrets.Secret, error)) *Connector {
	t.Helper()
	var resolver SecretResolver = resolverFunc(resolve)
	return &Connector{
		policy:   allowTestTargetPolicy{},
		resolver: resolver,
		client:   server.Client(),
	}
}

type allowTestTargetPolicy struct{}

func (allowTestTargetPolicy) Validate(ctx context.Context, rawURL string) (outbound.Target, error) {
	return outbound.Target{}, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type errorReadCloser struct{ err error }

func (reader errorReadCloser) Read([]byte) (int, error) { return 0, reader.err }
func (errorReadCloser) Close() error                    { return nil }

type testTimeoutError struct{}

func (testTimeoutError) Error() string   { return "test timeout" }
func (testTimeoutError) Timeout() bool   { return true }
func (testTimeoutError) Temporary() bool { return true }

type resolverFunc func(context.Context, secrets.Reference) (secrets.Secret, error)

func (resolve resolverFunc) Resolve(ctx context.Context, reference secrets.Reference) (secrets.Secret, error) {
	if resolve == nil {
		return secrets.Secret{}, secrets.ErrUnavailable
	}
	return resolve(ctx, reference)
}

func newCountingServer(t *testing.T, body string) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func validQuery(templateID string) datasource.NormalizedQuery {
	return datasource.NormalizedQuery{
		TemplateID: templateID, Version: 1, Service: "checkout-api", Environment: "prod",
		Start: time.Unix(1793772000, 0).UTC(), End: time.Unix(1793772300, 0).UTC(),
		Step: 30 * time.Second, MaxSeries: 4, MaxPoints: 16,
	}
}

func TestRuntimeQueryUsesGetThroughReadonlyGateway(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "readonly gateway rejects non GET", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/api/v1/query_range" || !strings.Contains(r.URL.Query().Get("query"), "container_memory_working_set_bytes") || r.URL.Query().Get("step") != "30s" {
			t.Errorf("runtime query did not use fixed GET endpoint: %v", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, prometheusResponse)
	}))
	defer server.Close()
	connector := newTestConnector(t, server, nil)
	_, err := connector.Query(context.Background(), Target{Endpoint: server.URL}, validQuery("prometheus.runtime.container.memory.v1"))
	if err != nil {
		t.Fatalf("runtime readonly query: %v", err)
	}
}
