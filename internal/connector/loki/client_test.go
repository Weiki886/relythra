package loki

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
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/security/secrets"
)

const lokiResponse = `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"service":"checkout-api","env":"prod","level":"ERROR"},"values":[["1793772240000000000","request failed token=loki-line-canary"],["1793772300000000000","database unavailable"]]}]}}`

func TestQueryUsesFixedBoundedLogQLAndReturnsRedactedUntrustedEntries(t *testing.T) {
	const canary = "loki-query-token-canary"
	reference, err := secrets.ParseReference("env:LOKI_QUERY_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/loki/api/v1/query_range" || request.URL.RawQuery != "" {
			t.Errorf("request = %s %s", request.Method, request.URL.String())
		}
		if request.Header.Get("Authorization") != "Bearer "+canary {
			t.Error("missing Loki read credential")
		}
		if err := request.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		query := request.Form.Get("query")
		if !strings.Contains(query, `{service="checkout-api",env="prod"}`) || strings.Contains(query, "caller-supplied") {
			t.Errorf("query is not fixed: %s", query)
		}
		if request.Form.Get("direction") != "backward" || request.Form.Get("limit") != "1000" {
			t.Errorf("query bounds = direction:%q limit:%q", request.Form.Get("direction"), request.Form.Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, lokiResponse)
	}))
	defer server.Close()

	connector := newTestConnector(t, server, func(_ context.Context, got secrets.Reference) (secrets.Secret, error) {
		if got.String() != reference.String() {
			t.Fatalf("secret reference = %q", got.String())
		}
		return secrets.New(canary)
	}, newTestFilter(t, canary, "loki-line-canary"))
	query := validQuery("loki.service.errors.v1")
	result, err := connector.Query(context.Background(), Target{Endpoint: server.URL, SecretReference: &reference}, query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if result.TemplateID != query.TemplateID || result.TemplateVersion != 1 || result.Empty || result.Partial || result.NextCursor != "" {
		t.Fatalf("result metadata = %+v", result)
	}
	if len(result.Entries) != 2 || result.Entries[0].Timestamp.Location() != time.UTC {
		t.Fatalf("entries = %+v", result.Entries)
	}
	if result.Entries[0].SourceTimestamp != "1793772300000000000" {
		t.Fatalf("backward query was not sorted newest first: %+v", result.Entries)
	}
	if result.Entries[0].Line.Trust != "untrusted_data" || strings.Contains(result.Entries[0].Line.Content, "loki-line-canary") || strings.Contains(result.SourceReference, canary) {
		t.Fatalf("unsafe entry or metadata = %+v", result)
	}
	if result.ResponseSHA256 == "" || result.Query == "" {
		t.Fatalf("missing trace metadata = %+v", result)
	}
}

func TestQueryRejectsUnknownTemplateBeforeNetwork(t *testing.T) {
	server, calls := newCountingServer(t, lokiResponse)
	connector := newTestConnector(t, server, nil, newTestFilter(t))
	_, err := connector.Query(context.Background(), Target{Endpoint: server.URL}, validQuery("loki.user.query.v1"))
	if !IsErrorCategory(err, ErrorInvalidQuery) || *calls != 0 {
		t.Fatalf("error=%v calls=%d", err, *calls)
	}
}

func TestQueryPaginatesBoundedSnapshotAndRejectsExpiredCursor(t *testing.T) {
	body := `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"service":"checkout-api","env":"prod"},"values":[["1793772240000000000","first"],["1793772300000000000","second"],["1793772360000000000","third"]]}]}}`
	server, calls := newCountingServer(t, body)
	connector := newTestConnector(t, server, nil, newTestFilter(t))
	query := validQuery("loki.service.errors.v1")
	query.Limit = 2
	first, err := connector.Query(context.Background(), Target{Endpoint: server.URL}, query)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first.Entries) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %+v", first)
	}
	query.Cursor = first.NextCursor
	second, err := connector.Query(context.Background(), Target{Endpoint: server.URL}, query)
	if err != nil || len(second.Entries) != 1 || second.NextCursor != "" || *calls != 2 {
		t.Fatalf("second page = %+v, err=%v calls=%d", second, err, *calls)
	}

	query.Cursor = first.NextCursor
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Replace(body, "third", "changed", 1))
	})
	_, err = connector.Query(context.Background(), Target{Endpoint: server.URL}, query)
	if !IsErrorCategory(err, ErrorCursorExpired) {
		t.Fatalf("error = %v, want expired cursor", err)
	}
}

func TestQueryCursorIsBoundToEndpoint(t *testing.T) {
	server, calls := newCountingServer(t, `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"service":"checkout-api","env":"prod"},"values":[["1793772240000000000","first"],["1793772300000000000","second"]]}]}}`)
	connector := newTestConnector(t, server, nil, newTestFilter(t))
	query := validQuery("loki.service.errors.v1")
	query.Limit = 1
	first, err := connector.Query(context.Background(), Target{Endpoint: server.URL}, query)
	if err != nil || first.NextCursor == "" {
		t.Fatalf("first page = %+v err=%v", first, err)
	}
	query.Cursor = first.NextCursor
	_, err = connector.Query(context.Background(), Target{Endpoint: "https://other.example.test"}, query)
	if !IsErrorCategory(err, ErrorInvalidCursor) || *calls != 1 {
		t.Fatalf("error=%v calls=%d", err, *calls)
	}
}

func TestQueryRejectsMalformedCursorBeforeNetwork(t *testing.T) {
	server, calls := newCountingServer(t, lokiResponse)
	connector := newTestConnector(t, server, nil, newTestFilter(t))
	query := validQuery("loki.service.errors.v1")
	query.Cursor = "not-a-valid-cursor"
	_, err := connector.Query(context.Background(), Target{Endpoint: server.URL}, query)
	if !IsErrorCategory(err, ErrorInvalidCursor) || *calls != 0 {
		t.Fatalf("error=%v calls=%d", err, *calls)
	}
}

func TestQueryRejectsCursorBoundToDifferentQueryBeforeNetwork(t *testing.T) {
	server, calls := newCountingServer(t, lokiResponse)
	connector := newTestConnector(t, server, nil, newTestFilter(t))
	query := validQuery("loki.service.errors.v1")
	query.Cursor = encodeCursor(pageCursor{
		Fingerprint: "different-query", ResponseDigest: strings.Repeat("a", 64), Offset: 1,
	})
	_, err := connector.Query(context.Background(), Target{Endpoint: server.URL}, query)
	if !IsErrorCategory(err, ErrorInvalidCursor) || *calls != 0 {
		t.Fatalf("error=%v calls=%d", err, *calls)
	}
}

func TestQueryClassifiesRemoteFailures(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		category ErrorCategory
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, category: ErrorUnauthorized},
		{name: "forbidden", status: http.StatusForbidden, category: ErrorUnauthorized},
		{name: "rate limited", status: http.StatusTooManyRequests, category: ErrorRateLimited},
		{name: "server error", status: http.StatusBadGateway, category: ErrorRemoteUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
			}))
			defer server.Close()
			_, err := newTestConnector(t, server, nil, newTestFilter(t)).Query(
				context.Background(), Target{Endpoint: server.URL}, validQuery("loki.service.errors.v1"),
			)
			if !IsErrorCategory(err, test.category) {
				t.Fatalf("error = %v, want %s", err, test.category)
			}
			if strings.Contains(err.Error(), server.URL) {
				t.Fatalf("error leaked endpoint: %v", err)
			}
		})
	}
}

func TestQueryMarksMalformedEntriesPartialAndPreservesClockDrift(t *testing.T) {
	body := `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"service":"checkout-api","env":"prod"},"values":[["1793772240000000000","outside-window"],["bad-time","discard me"]]}]}}`
	server, _ := newCountingServer(t, body)
	query := validQuery("loki.service.errors.v1")
	query.Start = time.Unix(1793772840, 0).UTC()
	query.End = time.Unix(1793773200, 0).UTC()
	result, err := newTestConnector(t, server, nil, newTestFilter(t)).Query(context.Background(), Target{Endpoint: server.URL}, query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !result.Partial || !result.TimeSkew || len(result.Entries) != 1 || !result.Entries[0].OutsideTimeWindow {
		t.Fatalf("partial/time drift result = %+v", result)
	}
}

func TestQueryRejectsResponseOverByteLimit(t *testing.T) {
	server, _ := newCountingServer(t, strings.Repeat("x", MaxResponseBytes+1))
	_, err := newTestConnector(t, server, nil, newTestFilter(t)).Query(context.Background(), Target{Endpoint: server.URL}, validQuery("loki.service.errors.v1"))
	if !IsErrorCategory(err, ErrorResponseTooLarge) {
		t.Fatalf("error = %v, want response too large", err)
	}
}

func TestQueryKeepsCompleteEntriesWhenResponseStreamTimesOutAfterPayload(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       &errorAfterPayload{payload: []byte(lokiResponse), err: testTimeoutError{}},
			Header:     make(http.Header),
		}, nil
	})}
	connector := &Connector{
		policy: allowTestTargetPolicy{}, resolver: resolverFunc(nil), filter: newTestFilter(t), client: client,
	}
	result, err := connector.Query(context.Background(), Target{Endpoint: "https://logs.example.test"}, validQuery("loki.service.errors.v1"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !result.Partial || len(result.Entries) != 2 {
		t.Fatalf("partial stream result = %+v", result)
	}
}

func TestBuildLogQLUsesRegisteredTemplatesAndEscapedSelectors(t *testing.T) {
	query := validQuery("loki.service.slow_queries.v1")
	query.Service = `checkout"-api`
	if _, err := buildLogQL(query); err == nil {
		t.Fatalf("invalid selector error = %v", err)
	}
	query.Service = "checkout-api"
	logQL, err := buildLogQL(query)
	if err != nil || !strings.HasPrefix(logQL, `{service="checkout-api",env="prod"}`) || !strings.Contains(logQL, "query_id") {
		t.Fatalf("LogQL=%q err=%v", logQL, err)
	}
}

func TestBuildLogQLUsesFixedTemplateAndSeverityFilters(t *testing.T) {
	tests := []struct {
		templateID string
		contains   string
	}{
		{templateID: "loki.service.errors.v1", contains: "error|exception|panic"},
		{templateID: "loki.service.slow_queries.v1", contains: "slow query|query_id"},
		{templateID: "loki.container.restarts.v1", contains: "oom|restart(ed)?"},
		{templateID: "loki.service.config_errors.v1", contains: "invalid config|configuration error"},
	}
	for _, test := range tests {
		query := validQuery(test.templateID)
		query.Severity = "error"
		logQL, err := buildLogQL(query)
		if err != nil || !strings.Contains(logQL, test.contains) || !strings.Contains(logQL, `\"level\"\\s*:\\s*\"error\"`) {
			t.Errorf("template %s LogQL=%q err=%v", test.templateID, logQL, err)
		}
	}
}

func TestQueryTruncatesOversizedLogLineAndMarksPartialOnWarnings(t *testing.T) {
	line := strings.Repeat("x", MaxLogLineBytes+256)
	body := `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"service":"checkout-api","env":"prod"},"values":[["1793772240000000000","` + line + `"]]}]},"warnings":["partial stream"]}`
	server, _ := newCountingServer(t, body)
	result, err := newTestConnector(t, server, nil, newTestFilter(t)).Query(context.Background(), Target{Endpoint: server.URL}, validQuery("loki.service.errors.v1"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !result.Partial || len(result.Entries) != 1 || !result.Entries[0].Line.Truncated || result.Entries[0].Line.OriginalBytes != len(line) {
		t.Fatalf("truncation result = %+v", result)
	}
}

func TestQueryEnforcesGlobalEntryCap(t *testing.T) {
	var values strings.Builder
	values.WriteString(`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"service":"checkout-api","env":"prod"},"values":[`)
	for index := 0; index < MaxQueryEntries+1; index++ {
		if index != 0 {
			values.WriteByte(',')
		}
		fmt.Fprintf(&values, `["1793772240000000000","line-%d"]`, index)
	}
	values.WriteString(`]}]}}`)
	server, _ := newCountingServer(t, values.String())
	query := validQuery("loki.service.errors.v1")
	query.Limit = datasource.MaxQueryLimit
	result, err := newTestConnector(t, server, nil, newTestFilter(t)).Query(context.Background(), Target{Endpoint: server.URL}, query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(result.Entries) != datasource.MaxQueryLimit || !result.Partial || result.NextCursor == "" {
		t.Fatalf("entry-cap result entries=%d partial=%v cursor=%q", len(result.Entries), result.Partial, result.NextCursor)
	}
}

func newTestConnector(
	t *testing.T,
	server *httptest.Server,
	resolve func(context.Context, secrets.Reference) (secrets.Secret, error),
	filter *redact.Filter,
) *Connector {
	t.Helper()
	var resolver SecretResolver = resolverFunc(resolve)
	return &Connector{policy: allowTestTargetPolicy{}, resolver: resolver, filter: filter, client: server.Client()}
}

func newTestFilter(t *testing.T, knownSecrets ...string) *redact.Filter {
	t.Helper()
	filter, err := redact.NewFilter(knownSecrets...)
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

type allowTestTargetPolicy struct{}

func (allowTestTargetPolicy) Validate(context.Context, string) (outbound.Target, error) {
	return outbound.Target{}, nil
}

type resolverFunc func(context.Context, secrets.Reference) (secrets.Secret, error)

func (resolve resolverFunc) Resolve(ctx context.Context, reference secrets.Reference) (secrets.Secret, error) {
	if resolve == nil {
		return secrets.Secret{}, secrets.ErrUnavailable
	}
	return resolve(ctx, reference)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type errorAfterPayload struct {
	payload []byte
	err     error
}

func (reader *errorAfterPayload) Read(buffer []byte) (int, error) {
	if len(reader.payload) == 0 {
		return 0, reader.err
	}
	n := copy(buffer, reader.payload)
	reader.payload = reader.payload[n:]
	return n, nil
}

func (*errorAfterPayload) Close() error { return nil }

type testTimeoutError struct{}

func (testTimeoutError) Error() string   { return "test timeout" }
func (testTimeoutError) Timeout() bool   { return true }
func (testTimeoutError) Temporary() bool { return true }

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
		Direction: "backward", Start: time.Unix(1793772000, 0).UTC(), End: time.Unix(1793772600, 0).UTC(),
		Limit: 20, MaxSeries: 100,
	}
}

func TestQueryUsesResolvedCredentialWithoutReadingReferenceAgain(t *testing.T) {
	const canary = "resolved-loki-credential-canary"
	reference, err := secrets.ParseReference("env:LOKI_QUERY_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := secrets.New(canary)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+canary {
			t.Error("wrong credential snapshot")
		}
		_, _ = io.WriteString(w, strings.ReplaceAll(lokiResponse, "database unavailable", "raw echo "+canary))
	}))
	defer server.Close()
	calls := 0
	connector := newTestConnector(t, server, func(context.Context, secrets.Reference) (secrets.Secret, error) {
		calls++
		return secrets.New("rotated-value")
	}, newTestFilter(t))
	result, err := connector.Query(context.Background(), Target{Endpoint: server.URL, SecretReference: &reference, ResolvedSecret: &secret}, validQuery("loki.service.errors.v1"))
	if err != nil || calls != 0 {
		t.Fatalf("query err=%v resolver calls=%d, want supplied snapshot", err, calls)
	}
	if len(result.Entries) == 0 || strings.Contains(result.Entries[0].Line.Content, canary) {
		t.Fatal("resolved credential echoed in connector output")
	}
}
