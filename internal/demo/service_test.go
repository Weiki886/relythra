package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stockFake struct {
	quantity    int
	err         error
	slowQueries chan struct{}
}

func (s stockFake) Stock(context.Context) (int, error) { return s.quantity, s.err }
func (s stockFake) SlowQuery(context.Context) error {
	if s.slowQueries != nil {
		select {
		case s.slowQueries <- struct{}{}:
		default:
		}
	}
	return s.err
}
func demoConfig(service string) Config {
	return Config{Service: service, Project: "relythra-demo", Environment: "demo", Release: "baseline", Host: "demo-host", Container: "test-container"}
}
func request(h http.Handler, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}
func TestOrdersCallsInventoryAndRecordsTelemetry(t *testing.T) {
	var logs bytes.Buffer
	inventory, err := NewHandler(demoConfig("inventory"), stockFake{quantity: 42}, nil, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(inventory)
	defer upstream.Close()
	cfg := demoConfig("orders")
	cfg.InventoryURL = upstream.URL
	orders, err := NewHandler(cfg, nil, upstream.Client(), slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	w := request(orders, "/orders")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"available":42`) {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	metrics := request(orders, "/metrics").Body.String()
	if !strings.Contains(metrics, `demo_service_info{project="relythra-demo",service="orders",env="demo",host="demo-host",container="test-container",release="baseline",runtime_type="docker-compose"} 1`) {
		t.Fatalf("missing explicit instance/release identity: %s", metrics)
	}
	for _, want := range []string{`demo_http_requests_total{service="orders",route="/orders",status="200"} 1`, `demo_http_request_duration_seconds_bucket`, `demo_http_request_duration_seconds_count{service="orders",route="/orders"} 1`} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("missing %s: %s", want, metrics)
		}
	}
	decoder := json.NewDecoder(&logs)
	for decoder.More() {
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"project", "service", "env", "host", "container", "runtime_type", "release"} {
			if event[key] == nil || event[key] == "" {
				t.Fatalf("missing log label %s: %v", key, event)
			}
		}
	}
}
func TestDependencyLossAffectsReadinessButNotLiveness(t *testing.T) {
	inventory, _ := NewHandler(demoConfig("inventory"), stockFake{err: errors.New("password=private-value")}, nil, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	upstream := httptest.NewServer(inventory)
	defer upstream.Close()
	cfg := demoConfig("orders")
	cfg.InventoryURL = upstream.URL
	orders, _ := NewHandler(cfg, nil, upstream.Client(), slog.Default())
	for _, h := range []http.Handler{inventory, orders} {
		for path, status := range map[string]int{"/health/ready": 503, "/health/live": 200} {
			if got := request(h, path); got.Code != status {
				t.Fatalf("%s = %d", path, got.Code)
			}
		}
	}
	if w := request(inventory, "/stock"); w.Code != 503 || strings.Contains(w.Body.String(), "private-value") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := request(orders, "/orders"); w.Code != 503 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
func TestRoutesAndFaultGate(t *testing.T) {
	cfg := demoConfig("inventory")
	handler, _ := NewHandler(cfg, stockFake{quantity: 1}, nil, slog.Default())
	for _, path := range []string{"/unknown-secret-path", "/internal/test/slow-query"} {
		if w := request(handler, path); w.Code != 404 {
			t.Fatalf("%s = %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "/stock", nil))
	if w.Code != 405 {
		t.Fatalf("POST = %d", w.Code)
	}
	if strings.Contains(request(handler, "/metrics").Body.String(), "unknown-secret-path") {
		t.Fatal("unbounded path label")
	}
	cfg.EnableFaults = true
	handler, _ = NewHandler(cfg, stockFake{}, nil, slog.Default())
	if w := request(handler, "/internal/test/slow-query"); w.Code != 200 {
		t.Fatalf("enabled fault = %d", w.Code)
	}
}

func TestInventoryStockSlowSQLFaultIsGated(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			slowQueries := make(chan struct{}, 1)
			cfg := demoConfig("inventory")
			cfg.EnableFaults = enabled
			handler, err := NewHandler(cfg, stockFake{quantity: 42, slowQueries: slowQueries}, nil, slog.Default())
			if err != nil {
				t.Fatal(err)
			}

			if response := request(handler, "/stock"); response.Code != http.StatusOK {
				t.Fatalf("stock status = %d, body=%s", response.Code, response.Body.String())
			}
			if got := len(slowQueries); (got == 1) != enabled {
				t.Fatalf("slow query calls = %d, fault enabled = %v", got, enabled)
			}
		})
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, cfg := range []Config{{}, demoConfig("other"), func() Config { c := demoConfig("orders"); c.InventoryURL = "http://user:secret@localhost"; return c }(), func() Config { c := demoConfig("inventory"); c.Host = ""; return c }()} {
		if _, err := NewHandler(cfg, nil, nil, slog.Default()); err == nil {
			t.Fatalf("accepted %+v", cfg)
		}
	}
}

func TestOrdersRejectsMissingOrOversizedInventoryData(t *testing.T) {
	for _, body := range []string{`{}`, `{"available":-1}`, strings.Repeat(" ", 4096) + `{"available":42}`, `{"available":42}` + strings.Repeat(" ", 4096)} {
		t.Run(body[:min(len(body), 30)], func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer upstream.Close()
			cfg := demoConfig("orders")
			cfg.InventoryURL = upstream.URL
			handler, err := NewHandler(cfg, nil, upstream.Client(), slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			if w := request(handler, "/orders"); w.Code != 503 {
				t.Fatalf("missing/invalid data treated as valid stock: %d %s", w.Code, w.Body)
			}
		})
	}
}
