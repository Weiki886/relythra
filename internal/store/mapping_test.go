package store

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestCreateDataSourceMappingAllowsDraftWithMissingRuntimeLabels(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "mapping-draft")
	repository := NewPostgres(db)

	mapping, issues, err := repository.CreateDataSourceMapping(ctx, CreateDataSourceMappingInput{
		ProjectID:   fixture.projectID,
		ServiceID:   fixture.serviceID,
		Environment: "prod",
		SourceType:  datasource.SourceRuntime,
		RuntimeType: datasource.RuntimeDockerCompose,
		PublicSettings: datasource.PublicSettings{
			Endpoint: "http://cadvisor:8080",
			ContainerMappings: []datasource.RuntimeContainerMapping{{
				HostID: "demo-host", CgroupID: "docker/cgroup-a",
			}},
		},
		TemplateIDs: []string{"runtime.containers.v1"},
		SecretRef:   "env:RUNTIME_TOKEN",
	})
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if mapping.Version != 1 {
		t.Fatalf("version = %d, want 1", mapping.Version)
	}
	if len(issues) != 5 {
		t.Fatalf("issues = %#v, want five missing labels", issues)
	}
	if mapping.SecretRef != "env:RUNTIME_TOKEN" {
		t.Fatalf("secret reference was not persisted")
	}
	if len(mapping.PublicSettings.ContainerMappings) != 1 || mapping.PublicSettings.ContainerMappings[0].HostID != "demo-host" || mapping.PublicSettings.ContainerMappings[0].CgroupID != "docker/cgroup-a" {
		t.Fatalf("runtime container mappings were not persisted: %+v", mapping.PublicSettings.ContainerMappings)
	}
	updated, _, err := repository.UpdateDataSourceMapping(ctx, UpdateDataSourceMappingInput{
		ID: mapping.ID, ExpectedVersion: mapping.Version, ProjectID: fixture.projectID, ServiceID: fixture.serviceID,
		Environment: "prod", SourceType: datasource.SourceRuntime, RuntimeType: datasource.RuntimeDockerCompose,
		PublicSettings: datasource.PublicSettings{
			Endpoint:          "http://cadvisor:8080",
			ContainerMappings: []datasource.RuntimeContainerMapping{{HostID: "demo-host", CgroupID: "docker/cgroup-b"}},
		},
		TemplateIDs: []string{"runtime.containers.v1"}, SecretRef: "env:RUNTIME_TOKEN",
	})
	if err != nil {
		t.Fatalf("update runtime mapping: %v", err)
	}
	if updated.Version != 2 || len(updated.PublicSettings.ContainerMappings) != 1 || updated.PublicSettings.ContainerMappings[0].CgroupID != "docker/cgroup-b" {
		t.Fatalf("updated versioned mapping = %+v", updated)
	}
}

func TestCreateDataSourceMappingRejectsInvalidEndpoint(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "mapping-invalid-endpoint")
	repository := NewPostgres(db)

	_, _, err := repository.CreateDataSourceMapping(ctx, prometheusMappingInput(
		fixture,
		"https://admin:password@metrics.example.com",
	))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}

func TestUpdateDataSourceMappingRejectsStaleVersion(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "mapping-version")
	repository := NewPostgres(db)
	mapping := createPrometheusMapping(t, repository, fixture)

	input := updatePrometheusMapping(mapping)
	input.ExpectedVersion = 2
	_, _, err := repository.UpdateDataSourceMapping(ctx, input)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestUpdateDataSourceMappingIncrementsVersion(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "mapping-update")
	repository := NewPostgres(db)
	mapping := createPrometheusMapping(t, repository, fixture)

	updated, issues, err := repository.UpdateDataSourceMapping(
		ctx,
		updatePrometheusMapping(mapping),
	)
	if err != nil {
		t.Fatalf("update mapping: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %#v", issues)
	}
	if updated.Version != 2 {
		t.Fatalf("version = %d, want 2", updated.Version)
	}
	if len(updated.Templates) != 2 {
		t.Fatalf("templates = %#v, want two templates", updated.Templates)
	}
}

func TestCreateDataSourceMappingRejectsDuplicateActiveIdentity(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "mapping-duplicate")
	repository := NewPostgres(db)
	_ = createPrometheusMapping(t, repository, fixture)

	_, _, err := repository.CreateDataSourceMapping(
		ctx,
		prometheusMappingInput(fixture, "https://metrics.example.com"),
	)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestCreateDataSourceMappingRejectsServiceFromAnotherProject(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	first := insertStoreFixture(t, ctx, db, "mapping-owner-first")
	second := insertStoreFixture(t, ctx, db, "mapping-owner-second")
	repository := NewPostgres(db)
	input := prometheusMappingInput(first, "https://metrics.example.com")
	input.ServiceID = second.serviceID

	_, _, err := repository.CreateDataSourceMapping(ctx, input)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}

func TestIsUniqueViolationUsesPostgresSQLState(t *testing.T) {
	pgError := fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "23505"})
	if !isUniqueViolation(pgError) {
		t.Fatal("wrapped SQLSTATE 23505 was not recognized")
	}
	if isUniqueViolation(errors.New("duplicate key value violates unique constraint")) {
		t.Fatal("error text alone must not be treated as a PostgreSQL SQLSTATE")
	}
}

func TestDataSourceMappingSoftDeleteAllowsRecreation(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "mapping-soft-delete")
	repository := NewPostgres(db)
	first := createPrometheusMapping(t, repository, fixture)

	if err := repository.DeleteDataSourceMapping(ctx, first.ID, first.Version); err != nil {
		t.Fatalf("delete mapping: %v", err)
	}
	_, err := repository.GetDataSourceMapping(ctx, first.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted mapping error = %v, want ErrNotFound", err)
	}

	second, issues, err := repository.CreateDataSourceMapping(
		ctx,
		prometheusMappingInput(fixture, "https://metrics.example.com"),
	)
	if err != nil {
		t.Fatalf("recreate mapping: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %#v", issues)
	}
	if second.ID == first.ID {
		t.Fatal("recreated mapping reused the deleted row")
	}
}

func TestListDataSourceMappingsFiltersActiveProjectServiceAndEnvironment(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	fixture := insertStoreFixture(t, ctx, db, "mapping-list")
	repository := NewPostgres(db)
	created := createPrometheusMapping(t, repository, fixture)

	mappings, err := repository.ListDataSourceMappings(
		ctx,
		fixture.projectID,
		fixture.serviceID,
		"prod",
	)
	if err != nil {
		t.Fatalf("list mappings: %v", err)
	}
	if len(mappings) != 1 || mappings[0].ID != created.ID {
		t.Fatalf("mappings = %#v", mappings)
	}
	if mappings[0].Templates[0].ID != "prometheus.service.latency.v1" {
		t.Fatalf("templates = %#v", mappings[0].Templates)
	}
}

func createPrometheusMapping(
	t *testing.T,
	repository *Postgres,
	fixture storeFixture,
) DataSourceMapping {
	t.Helper()
	mapping, issues, err := repository.CreateDataSourceMapping(
		context.Background(),
		prometheusMappingInput(fixture, "https://metrics.example.com"),
	)
	if err != nil {
		t.Fatalf("create mapping: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("create mapping issues: %#v", issues)
	}
	return mapping
}

func prometheusMappingInput(
	fixture storeFixture,
	endpoint string,
) CreateDataSourceMappingInput {
	return CreateDataSourceMappingInput{
		ProjectID:   fixture.projectID,
		ServiceID:   fixture.serviceID,
		Environment: "prod",
		SourceType:  datasource.SourcePrometheus,
		PublicSettings: datasource.PublicSettings{
			Endpoint: endpoint,
		},
		TemplateIDs: []string{"prometheus.service.latency.v1"},
		SecretRef:   "env:PROMETHEUS_TOKEN",
	}
}

func updatePrometheusMapping(mapping DataSourceMapping) UpdateDataSourceMappingInput {
	return UpdateDataSourceMappingInput{
		ID:              mapping.ID,
		ExpectedVersion: mapping.Version,
		ProjectID:       mapping.ProjectID,
		ServiceID:       mapping.ServiceID,
		Environment:     mapping.Environment,
		SourceType:      mapping.SourceType,
		RuntimeType:     mapping.RuntimeType,
		PublicSettings:  mapping.PublicSettings,
		TemplateIDs: []string{
			"prometheus.service.latency.v1",
			"prometheus.container.memory.v1",
		},
		SecretRef: mapping.SecretRef,
	}
}
