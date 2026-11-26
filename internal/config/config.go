package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Weiki886/relythra/internal/security/outbound"
	"github.com/Weiki886/relythra/internal/security/secrets"
)

const (
	defaultAPIAddress         = ":8080"
	defaultWorkerAddress      = ":8081"
	defaultShutdownTimeout    = 10 * time.Second
	defaultHeartbeatInterval  = 5 * time.Second
	defaultWorkerPollInterval = time.Second
)

type API struct {
	Address                 string
	DatabaseURL             secrets.Secret
	AdminToken              secrets.Secret
	DeploymentWebhookSecret secrets.Secret
	DeploymentWebhookSource string
	GrafanaWebhookSecret    secrets.Secret
	ManagementActor         string
	DataSourcePolicy        outbound.PolicyConfig
	ShutdownTimeout         time.Duration
}

var deploymentSourcePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type Worker struct {
	Address           string
	HeartbeatInterval time.Duration
	PollInterval      time.Duration
	DatabaseURL       secrets.Secret
	DataSourcePolicy  outbound.PolicyConfig
}

func LoadAPI(getenv func(string) string) (API, error) {
	if getenv == nil {
		return API{}, fmt.Errorf("environment lookup is required")
	}
	databaseURL, err := loadDatabaseURL(getenv)
	if err != nil {
		return API{}, err
	}

	shutdownTimeout, err := positiveDuration(getenv, "RELYTHRA_SHUTDOWN_TIMEOUT", defaultShutdownTimeout)
	if err != nil {
		return API{}, err
	}
	adminToken, err := loadAdminToken(getenv)
	if err != nil {
		return API{}, err
	}
	deploymentWebhookSecret, deploymentWebhookSource, err := loadDeploymentWebhook(getenv)
	if err != nil {
		return API{}, err
	}
	grafanaWebhookSecret, err := loadGrafanaWebhook(getenv)
	if err != nil {
		return API{}, err
	}
	dataSourcePolicy, err := loadDataSourcePolicy(getenv)
	if err != nil {
		return API{}, err
	}

	return API{
		Address:                 valueOrDefault(getenv("RELYTHRA_API_ADDR"), defaultAPIAddress),
		DatabaseURL:             databaseURL,
		AdminToken:              adminToken,
		DeploymentWebhookSecret: deploymentWebhookSecret,
		DeploymentWebhookSource: deploymentWebhookSource,
		GrafanaWebhookSecret:    grafanaWebhookSecret,
		ManagementActor:         valueOrDefault(strings.TrimSpace(getenv("RELYTHRA_MANAGEMENT_ACTOR")), "management-token"),
		DataSourcePolicy:        dataSourcePolicy,
		ShutdownTimeout:         shutdownTimeout,
	}, nil
}

func loadGrafanaWebhook(getenv func(string) string) (secrets.Secret, error) {
	rawReference := strings.TrimSpace(getenv("RELYTHRA_GRAFANA_WEBHOOK_SECRET_REF"))
	if rawReference == "" {
		return secrets.Secret{}, nil
	}
	reference, err := secrets.ParseReference(rawReference)
	if err != nil {
		return secrets.Secret{}, fmt.Errorf("RELYTHRA_GRAFANA_WEBHOOK_SECRET_REF is invalid")
	}
	secret, err := secrets.NewResolver(nil, nil).Resolve(context.Background(), reference)
	if err != nil || secret.Reveal() == "" {
		return secrets.Secret{}, fmt.Errorf("RELYTHRA_GRAFANA_WEBHOOK_SECRET_REF could not be resolved")
	}
	return secret, nil
}

func loadDeploymentWebhook(getenv func(string) string) (secrets.Secret, string, error) {
	rawReference := strings.TrimSpace(getenv("RELYTHRA_DEPLOYMENT_WEBHOOK_SECRET_REF"))
	source := strings.TrimSpace(getenv("RELYTHRA_DEPLOYMENT_WEBHOOK_SOURCE"))
	if rawReference == "" && source == "" {
		return secrets.Secret{}, "", nil
	}
	if rawReference == "" || !deploymentSourcePattern.MatchString(source) {
		return secrets.Secret{}, "", fmt.Errorf("deployment webhook secret reference and valid source are required together")
	}
	reference, err := secrets.ParseReference(rawReference)
	if err != nil {
		return secrets.Secret{}, "", fmt.Errorf("RELYTHRA_DEPLOYMENT_WEBHOOK_SECRET_REF is invalid")
	}
	secret, err := secrets.NewResolver(nil, nil).Resolve(context.Background(), reference)
	if err != nil || secret.Reveal() == "" {
		return secrets.Secret{}, "", fmt.Errorf("RELYTHRA_DEPLOYMENT_WEBHOOK_SECRET_REF could not be resolved")
	}
	return secret, source, nil
}

func loadAdminToken(getenv func(string) string) (secrets.Secret, error) {
	rawReference := strings.TrimSpace(getenv("RELYTHRA_ADMIN_TOKEN_REF"))
	if rawReference == "" {
		return secrets.Secret{}, nil
	}
	reference, err := secrets.ParseReference(rawReference)
	if err != nil {
		return secrets.Secret{}, fmt.Errorf("RELYTHRA_ADMIN_TOKEN_REF is invalid")
	}
	token, err := secrets.NewResolver(nil, nil).Resolve(context.Background(), reference)
	if err != nil {
		return secrets.Secret{}, fmt.Errorf("RELYTHRA_ADMIN_TOKEN_REF could not be resolved")
	}
	return token, nil
}

func loadDataSourcePolicy(getenv func(string) string) (outbound.PolicyConfig, error) {
	rawHosts := strings.TrimSpace(getenv("RELYTHRA_DATASOURCE_ALLOWED_HOSTS"))
	rawPorts := strings.TrimSpace(getenv("RELYTHRA_DATASOURCE_ALLOWED_PORTS"))
	rawAllowHTTP := strings.TrimSpace(getenv("RELYTHRA_DATASOURCE_ALLOW_HTTP"))
	rawAllowPrivate := strings.TrimSpace(getenv("RELYTHRA_DATASOURCE_ALLOW_PRIVATE"))
	if rawHosts == "" && rawPorts == "" && rawAllowHTTP == "" && rawAllowPrivate == "" {
		return outbound.PolicyConfig{}, nil
	}
	if rawHosts == "" || rawPorts == "" {
		return outbound.PolicyConfig{}, fmt.Errorf(
			"RELYTHRA_DATASOURCE_ALLOWED_HOSTS and RELYTHRA_DATASOURCE_ALLOWED_PORTS are required together",
		)
	}

	hosts, err := commaSeparatedValues(rawHosts)
	if err != nil {
		return outbound.PolicyConfig{}, fmt.Errorf("RELYTHRA_DATASOURCE_ALLOWED_HOSTS is invalid")
	}
	portValues, err := commaSeparatedValues(rawPorts)
	if err != nil {
		return outbound.PolicyConfig{}, fmt.Errorf("RELYTHRA_DATASOURCE_ALLOWED_PORTS is invalid")
	}
	ports := make([]int, 0, len(portValues))
	for _, rawPort := range portValues {
		port, parseErr := strconv.Atoi(rawPort)
		if parseErr != nil || port < 1 || port > 65535 {
			return outbound.PolicyConfig{}, fmt.Errorf("RELYTHRA_DATASOURCE_ALLOWED_PORTS is invalid")
		}
		ports = append(ports, port)
	}
	allowHTTP, err := optionalBoolean(rawAllowHTTP, "RELYTHRA_DATASOURCE_ALLOW_HTTP")
	if err != nil {
		return outbound.PolicyConfig{}, err
	}
	allowPrivate, err := optionalBoolean(rawAllowPrivate, "RELYTHRA_DATASOURCE_ALLOW_PRIVATE")
	if err != nil {
		return outbound.PolicyConfig{}, err
	}

	policy := outbound.PolicyConfig{
		AllowedHosts: hosts,
		AllowedPorts: ports,
		AllowHTTP:    allowHTTP,
		AllowPrivate: allowPrivate,
	}
	if _, err := outbound.NewPolicy(policy); err != nil {
		return outbound.PolicyConfig{}, fmt.Errorf("data source policy is invalid")
	}
	return policy, nil
}

func commaSeparatedValues(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			return nil, errors.New("empty list item")
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil, errors.New("empty list")
	}
	return values, nil
}

func optionalBoolean(raw string, key string) (bool, error) {
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", key)
	}
	return value, nil
}

func loadDatabaseURL(getenv func(string) string) (secrets.Secret, error) {
	resolver := secrets.NewResolver(nil, nil)
	ctx := context.Background()

	if rawReference := strings.TrimSpace(getenv("RELYTHRA_DATABASE_URL_REF")); rawReference != "" {
		reference, err := secrets.ParseReference(rawReference)
		if err != nil {
			return secrets.Secret{}, fmt.Errorf("RELYTHRA_DATABASE_URL_REF is invalid")
		}
		value, err := resolver.Resolve(ctx, reference)
		if err != nil {
			return secrets.Secret{}, fmt.Errorf("RELYTHRA_DATABASE_URL_REF could not be resolved")
		}
		return value, nil
	}

	if rawReference := strings.TrimSpace(getenv("RELYTHRA_DATABASE_PASSWORD_REF")); rawReference != "" {
		return buildDatabaseURL(getenv, resolver, rawReference)
	}

	rawURL := strings.TrimSpace(getenv("RELYTHRA_DATABASE_URL"))
	if rawURL == "" {
		return secrets.Secret{}, fmt.Errorf(
			"RELYTHRA_DATABASE_URL, RELYTHRA_DATABASE_URL_REF, or RELYTHRA_DATABASE_PASSWORD_REF is required",
		)
	}
	value, err := secrets.New(rawURL)
	if err != nil {
		return secrets.Secret{}, fmt.Errorf("RELYTHRA_DATABASE_URL is invalid")
	}
	return value, nil
}

func buildDatabaseURL(
	getenv func(string) string,
	resolver *secrets.Resolver,
	rawReference string,
) (secrets.Secret, error) {
	reference, err := secrets.ParseReference(rawReference)
	if err != nil {
		return secrets.Secret{}, fmt.Errorf("RELYTHRA_DATABASE_PASSWORD_REF is invalid")
	}
	password, err := resolver.Resolve(context.Background(), reference)
	if err != nil {
		return secrets.Secret{}, fmt.Errorf("RELYTHRA_DATABASE_PASSWORD_REF could not be resolved")
	}

	host := strings.Trim(strings.TrimSpace(getenv("RELYTHRA_DATABASE_HOST")), "[]")
	port := valueOrDefault(getenv("RELYTHRA_DATABASE_PORT"), "5432")
	name := strings.TrimSpace(getenv("RELYTHRA_DATABASE_NAME"))
	user := strings.TrimSpace(getenv("RELYTHRA_DATABASE_USER"))
	sslMode := valueOrDefault(getenv("RELYTHRA_DATABASE_SSL_MODE"), "disable")

	portNumber, portErr := strconv.Atoi(port)
	if host == "" || strings.ContainsAny(host, "/\\?#@ \t\r\n") ||
		portErr != nil || portNumber < 1 || portNumber > 65535 ||
		name == "" || strings.ContainsAny(name, "/\\?# \t\r\n") ||
		user == "" || strings.ContainsAny(user, "/\\?#@ \t\r\n") ||
		!allowedSSLMode(sslMode) {
		return secrets.Secret{}, fmt.Errorf("database connection fields are invalid")
	}

	databaseURL := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password.Reveal()),
		Host:   net.JoinHostPort(host, port),
		Path:   "/" + name,
		RawQuery: url.Values{
			"sslmode": {sslMode},
		}.Encode(),
	}
	value, err := secrets.New(databaseURL.String())
	if err != nil {
		return secrets.Secret{}, fmt.Errorf("database connection URL is invalid")
	}
	return value, nil
}

func allowedSSLMode(value string) bool {
	switch value {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
		return true
	default:
		return false
	}
}

func LoadWorker(getenv func(string) string) (Worker, error) {
	if getenv == nil {
		return Worker{}, fmt.Errorf("environment lookup is required")
	}
	databaseURL, err := loadDatabaseURL(getenv)
	if err != nil {
		return Worker{}, err
	}
	dataSourcePolicy, err := loadDataSourcePolicy(getenv)
	if err != nil {
		return Worker{}, err
	}
	if len(dataSourcePolicy.AllowedHosts) == 0 || len(dataSourcePolicy.AllowedPorts) == 0 {
		return Worker{}, fmt.Errorf("RELYTHRA_DATASOURCE_ALLOWED_HOSTS and RELYTHRA_DATASOURCE_ALLOWED_PORTS are required for worker collection")
	}
	heartbeatInterval, err := positiveDuration(getenv, "RELYTHRA_WORKER_HEARTBEAT_INTERVAL", defaultHeartbeatInterval)
	if err != nil {
		return Worker{}, err
	}
	pollInterval, err := positiveDuration(getenv, "RELYTHRA_WORKER_POLL_INTERVAL", defaultWorkerPollInterval)
	if err != nil {
		return Worker{}, err
	}

	return Worker{
		Address:           valueOrDefault(getenv("RELYTHRA_WORKER_ADDR"), defaultWorkerAddress),
		HeartbeatInterval: heartbeatInterval,
		PollInterval:      pollInterval,
		DatabaseURL:       databaseURL,
		DataSourcePolicy:  dataSourcePolicy,
	}, nil
}

func positiveDuration(getenv func(string) string, key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return fallback, nil
	}

	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", key)
	}
	return value, nil
}

func valueOrDefault(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
