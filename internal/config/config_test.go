package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weiki886/relythra/internal/config"
)

func environment(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestLoadAPIUsesDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadAPI(environment(map[string]string{
		"RELYTHRA_DATABASE_URL": "postgres://localhost/relythra",
	}))
	if err != nil {
		t.Fatalf("LoadAPI() error = %v", err)
	}
	if cfg.Address != ":8080" {
		t.Errorf("Address = %q, want :8080", cfg.Address)
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 10s", cfg.ShutdownTimeout)
	}
	if cfg.DatabaseURL.Reveal() != "postgres://localhost/relythra" {
		t.Fatal("database URL was not resolved")
	}
}

func TestLoadAPIRequiresDatabaseURL(t *testing.T) {
	t.Parallel()

	_, err := config.LoadAPI(environment(nil))
	if err == nil {
		t.Fatal("LoadAPI() error = nil, want missing database URL error")
	}
}

func TestLoadAPIRejectsInvalidShutdownTimeout(t *testing.T) {
	t.Parallel()

	_, err := config.LoadAPI(environment(map[string]string{
		"RELYTHRA_DATABASE_URL":     "postgres://localhost/relythra",
		"RELYTHRA_SHUTDOWN_TIMEOUT": "forever",
	}))
	if err == nil {
		t.Fatal("LoadAPI() error = nil, want invalid duration error")
	}
}

func TestLoadAPIResolvesManagementAndDatasourcePolicy(t *testing.T) {
	t.Setenv("RELYTHRA_TEST_ADMIN_TOKEN", "management-token-canary")

	cfg, err := config.LoadAPI(environment(map[string]string{
		"RELYTHRA_DATABASE_URL":             "postgres://localhost/relythra",
		"RELYTHRA_ADMIN_TOKEN_REF":          "env:RELYTHRA_TEST_ADMIN_TOKEN",
		"RELYTHRA_DATASOURCE_ALLOWED_HOSTS": "metrics.example.test,logs.example.test",
		"RELYTHRA_DATASOURCE_ALLOWED_PORTS": "443,8443",
		"RELYTHRA_DATASOURCE_ALLOW_HTTP":    "true",
		"RELYTHRA_DATASOURCE_ALLOW_PRIVATE": "false",
	}))
	if err != nil {
		t.Fatalf("LoadAPI() error = %v", err)
	}
	if cfg.AdminToken.Reveal() != "management-token-canary" {
		t.Fatal("management token was not resolved")
	}
	if strings.Join(cfg.DataSourcePolicy.AllowedHosts, ",") !=
		"metrics.example.test,logs.example.test" {
		t.Fatalf("allowed hosts = %#v", cfg.DataSourcePolicy.AllowedHosts)
	}
	if len(cfg.DataSourcePolicy.AllowedPorts) != 2 ||
		cfg.DataSourcePolicy.AllowedPorts[0] != 443 ||
		cfg.DataSourcePolicy.AllowedPorts[1] != 8443 {
		t.Fatalf("allowed ports = %#v", cfg.DataSourcePolicy.AllowedPorts)
	}
	if !cfg.DataSourcePolicy.AllowHTTP || cfg.DataSourcePolicy.AllowPrivate {
		t.Fatalf("policy booleans = %+v", cfg.DataSourcePolicy)
	}
	if strings.Contains(fmt.Sprintf("%+v", cfg), "management-token-canary") {
		t.Fatal("formatted API config exposed the management token")
	}
}

func TestLoadAPIResolvesDeploymentWebhookSecretAndSource(t *testing.T) {
	t.Setenv("RELYTHRA_TEST_DEPLOYMENT_SECRET", "deployment-webhook-canary")
	cfg, err := config.LoadAPI(environment(map[string]string{
		"RELYTHRA_DATABASE_URL":                  "postgres://localhost/relythra",
		"RELYTHRA_DEPLOYMENT_WEBHOOK_SECRET_REF": "env:RELYTHRA_TEST_DEPLOYMENT_SECRET",
		"RELYTHRA_DEPLOYMENT_WEBHOOK_SOURCE":     "github-actions",
	}))
	if err != nil {
		t.Fatalf("LoadAPI() error = %v", err)
	}
	if cfg.DeploymentWebhookSecret.Reveal() != "deployment-webhook-canary" || cfg.DeploymentWebhookSource != "github-actions" {
		t.Fatalf("deployment webhook configuration was not loaded: source=%q", cfg.DeploymentWebhookSource)
	}
	if strings.Contains(fmt.Sprintf("%+v", cfg), "deployment-webhook-canary") {
		t.Fatal("formatted API config exposed deployment webhook secret")
	}
}

func TestLoadAPIResolvesDedicatedGrafanaWebhookSecret(t *testing.T) {
	t.Setenv("RELYTHRA_TEST_GRAFANA_SECRET", "grafana-webhook-canary")
	cfg, err := config.LoadAPI(environment(map[string]string{
		"RELYTHRA_DATABASE_URL":               "postgres://localhost/relythra",
		"RELYTHRA_GRAFANA_WEBHOOK_SECRET_REF": "env:RELYTHRA_TEST_GRAFANA_SECRET",
	}))
	if err != nil {
		t.Fatalf("LoadAPI() error = %v", err)
	}
	if cfg.GrafanaWebhookSecret.Reveal() != "grafana-webhook-canary" {
		t.Fatal("Grafana webhook secret was not resolved")
	}
	if strings.Contains(fmt.Sprintf("%+v", cfg), "grafana-webhook-canary") {
		t.Fatal("formatted API config exposed Grafana webhook secret")
	}
}

func TestLoadAPIRejectsDeploymentWebhookSecretWithoutSource(t *testing.T) {
	t.Setenv("RELYTHRA_TEST_DEPLOYMENT_SECRET", "deployment-webhook-canary")
	if _, err := config.LoadAPI(environment(map[string]string{
		"RELYTHRA_DATABASE_URL":                  "postgres://localhost/relythra",
		"RELYTHRA_DEPLOYMENT_WEBHOOK_SECRET_REF": "env:RELYTHRA_TEST_DEPLOYMENT_SECRET",
	})); err == nil {
		t.Fatal("webhook secret without a source identity was accepted")
	}
}

func TestLoadAPIRejectsIncompleteManagementPolicy(t *testing.T) {
	t.Setenv("RELYTHRA_TEST_ADMIN_TOKEN", "management-token-canary")

	tests := []struct {
		name   string
		values map[string]string
	}{
		{
			name: "missing hosts",
			values: map[string]string{
				"RELYTHRA_DATASOURCE_ALLOWED_PORTS": "443",
			},
		},
		{
			name: "invalid port",
			values: map[string]string{
				"RELYTHRA_DATASOURCE_ALLOWED_HOSTS": "metrics.example.test",
				"RELYTHRA_DATASOURCE_ALLOWED_PORTS": "443,70000",
			},
		},
		{
			name: "invalid boolean",
			values: map[string]string{
				"RELYTHRA_DATASOURCE_ALLOWED_HOSTS": "metrics.example.test",
				"RELYTHRA_DATASOURCE_ALLOWED_PORTS": "443",
				"RELYTHRA_DATASOURCE_ALLOW_HTTP":    "sometimes",
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			values := map[string]string{
				"RELYTHRA_DATABASE_URL":    "postgres://localhost/relythra",
				"RELYTHRA_ADMIN_TOKEN_REF": "env:RELYTHRA_TEST_ADMIN_TOKEN",
			}
			for key, value := range testCase.values {
				values[key] = value
			}
			if _, err := config.LoadAPI(environment(values)); err == nil {
				t.Fatal("LoadAPI() error = nil, want invalid policy error")
			}
		})
	}
}

func TestLoadAPIResolvesDatabaseURLReference(t *testing.T) {
	t.Setenv("RELYTHRA_TEST_DATABASE_SECRET", "postgres://reader:canary@database/relythra")

	cfg, err := config.LoadAPI(environment(map[string]string{
		"RELYTHRA_DATABASE_URL_REF": "env:RELYTHRA_TEST_DATABASE_SECRET",
	}))
	if err != nil {
		t.Fatalf("LoadAPI() error = %v", err)
	}
	if cfg.DatabaseURL.Reveal() != "postgres://reader:canary@database/relythra" {
		t.Fatal("database URL reference was not resolved")
	}
	if strings.Contains(fmt.Sprintf("%+v", cfg), "canary") {
		t.Fatalf("formatted config exposed database secret: %+v", cfg)
	}
}

func TestLoadAPIBuildsDatabaseURLFromSecretFile(t *testing.T) {
	const canary = "compose-file-canary-4e80"
	secretFile := filepath.Join(t.TempDir(), "postgres-password")
	if err := os.WriteFile(secretFile, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatalf("write secret fixture: %v", err)
	}

	cfg, err := config.LoadAPI(environment(map[string]string{
		"RELYTHRA_DATABASE_HOST":         "database.internal",
		"RELYTHRA_DATABASE_PORT":         "6432",
		"RELYTHRA_DATABASE_NAME":         "relythra",
		"RELYTHRA_DATABASE_USER":         "diagnoser",
		"RELYTHRA_DATABASE_PASSWORD_REF": "file:" + secretFile,
		"RELYTHRA_DATABASE_SSL_MODE":     "require",
	}))
	if err != nil {
		t.Fatalf("LoadAPI() error = %v", err)
	}
	databaseURL := cfg.DatabaseURL.Reveal()
	for _, expected := range []string{
		"postgres://diagnoser:",
		"@database.internal:6432/relythra",
		"sslmode=require",
	} {
		if !strings.Contains(databaseURL, expected) {
			t.Errorf("database URL missing %q", expected)
		}
	}
	if !strings.Contains(databaseURL, canary) {
		t.Fatal("database URL did not include resolved password")
	}
}

func TestLoadAPIRejectsIncompleteDatabaseSecretConfiguration(t *testing.T) {
	const canary = "missing-parts-canary-90fa"
	_, err := config.LoadAPI(environment(map[string]string{
		"RELYTHRA_DATABASE_PASSWORD_REF": "env:RELYTHRA_TEST_MISSING_PASSWORD",
	}))
	if err == nil {
		t.Fatal("incomplete database configuration was accepted")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatal("configuration error exposed a secret")
	}
}

func TestLoadWorkerUsesDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadWorker(environment(map[string]string{
		"RELYTHRA_DATABASE_URL":             "postgres://localhost/relythra",
		"RELYTHRA_DATASOURCE_ALLOWED_HOSTS": "prometheus",
		"RELYTHRA_DATASOURCE_ALLOWED_PORTS": "9090",
		"RELYTHRA_DATASOURCE_ALLOW_HTTP":    "true",
		"RELYTHRA_DATASOURCE_ALLOW_PRIVATE": "true",
	}))
	if err != nil {
		t.Fatalf("LoadWorker() error = %v", err)
	}
	if cfg.Address != ":8081" {
		t.Errorf("Address = %q, want :8081", cfg.Address)
	}
	if cfg.HeartbeatInterval != 5*time.Second {
		t.Errorf("HeartbeatInterval = %v, want 5s", cfg.HeartbeatInterval)
	}
	if cfg.PollInterval != time.Second {
		t.Errorf("PollInterval = %v, want 1s", cfg.PollInterval)
	}
	if cfg.DatabaseURL.Reveal() != "postgres://localhost/relythra" || len(cfg.DataSourcePolicy.AllowedHosts) != 1 || cfg.DataSourcePolicy.AllowedHosts[0] != "prometheus" {
		t.Fatal("worker database or outbound policy was not loaded")
	}
}

func TestLoadWorkerRequiresDatabaseAndOutboundPolicy(t *testing.T) {
	t.Parallel()

	for name, values := range map[string]map[string]string{
		"database": {
			"RELYTHRA_DATASOURCE_ALLOWED_HOSTS": "prometheus",
			"RELYTHRA_DATASOURCE_ALLOWED_PORTS": "9090",
		},
		"outbound policy": {
			"RELYTHRA_DATABASE_URL": "postgres://localhost/relythra",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := config.LoadWorker(environment(values)); err == nil {
				t.Fatalf("LoadWorker(%s missing) error = nil", name)
			}
		})
	}
}

func TestLoadWorkerRejectsNonPositiveHeartbeatInterval(t *testing.T) {
	t.Parallel()

	_, err := config.LoadWorker(environment(map[string]string{
		"RELYTHRA_DATABASE_URL":              "postgres://localhost/relythra",
		"RELYTHRA_DATASOURCE_ALLOWED_HOSTS":  "prometheus",
		"RELYTHRA_DATASOURCE_ALLOWED_PORTS":  "9090",
		"RELYTHRA_WORKER_HEARTBEAT_INTERVAL": "0s",
	}))
	if err == nil {
		t.Fatal("LoadWorker() error = nil, want positive duration error")
	}
}
