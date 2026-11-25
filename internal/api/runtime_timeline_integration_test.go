package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	prometheusconnector "github.com/Weiki886/relythra/internal/connector/prometheus"
	runtimeconnector "github.com/Weiki886/relythra/internal/connector/runtime"
	"github.com/Weiki886/relythra/internal/datasource"
	"github.com/Weiki886/relythra/internal/evidence"
	"github.com/Weiki886/relythra/internal/security/redact"
	"github.com/Weiki886/relythra/internal/store"
)

func TestPersistedRuntimeEvidenceAppearsInInvestigationTimeline(t *testing.T) {
	db := openDiagnosisTestDB(t)
	ctx := context.Background()
	investigationID, serviceID := insertDiagnosisFixture(t, db)
	start := time.Date(2026, 11, 24, 2, 0, 0, 0, time.UTC)
	end := start.Add(5 * time.Minute)
	collectedAt := end.Add(time.Minute)
	prometheusReference := "https://prometheus.example.test/api/v1/query_range"
	lokiReference := "https://loki.example.test/loki/api/v1/query_range"

	measurement := func(value float64, reference string) runtimeconnector.Measurement {
		return runtimeconnector.Measurement{
			Samples:         []prometheusconnector.Sample{{Timestamp: start.Add(time.Minute), Value: value}},
			SourceReference: reference,
			Delay:           time.Minute,
		}
	}
	containerStart := start.Add(-time.Hour)
	result := runtimeconnector.Result{
		Runtime: datasource.RuntimeDockerCompose, Service: "checkout-api", Environment: "prod", HostID: "host-a", MappingVersion: 3,
		Start: start, End: end, Duration: 2 * time.Second,
		Hosts: []runtimeconnector.Host{{
			HostID: "host-a", Instance: "node:9100",
			CPU: measurement(0.4, prometheusReference), MemoryAvailable: measurement(2048, prometheusReference),
			Load: measurement(1.2, prometheusReference),
		}},
		Containers: []runtimeconnector.Container{{
			ID: "opaque-cgroup-a", InstanceID: "opaque-instance-a", HostID: "host-a", Service: "checkout-api",
			MappingStatus: "explicit_mapping", MappingVersion: 3, StartTime: &containerStart,
			StartEvidence: measurement(float64(containerStart.Unix()), prometheusReference),
			CPU:           measurement(0.1, prometheusReference), Memory: measurement(1024, prometheusReference),
			OOMEvents: measurement(0, prometheusReference), State: "observed", PeerContainerIDs: []string{},
		}},
		Events: []runtimeconnector.Event{{
			Timestamp: start.Add(2 * time.Minute), ContainerID: "opaque-cgroup-a", MappingVersion: 3,
			Classification: "unverified_log_match", SourceReference: lokiReference,
			Line: redact.UntrustedData{Trust: "untrusted_data", Source: "loki", Content: "container restart observed", OriginalBytes: 27},
		}},
		Gaps: []string{"healthy_peer_evidence_unavailable"}, Partial: true,
	}
	filter, err := redact.NewFilter()
	if err != nil {
		t.Fatal(err)
	}
	repository := store.NewPostgres(db)
	persisted, created, err := repository.PersistRuntimeEvidence(ctx, result, store.RuntimeEvidencePersistenceContext{
		InvestigationID: investigationID, ServiceID: serviceID, CollectedAt: collectedAt,
	}, filter)
	if err != nil {
		t.Fatalf("persist runtime evidence: %v", err)
	}
	if len(persisted) != 8 || len(created) != len(persisted) {
		t.Fatalf("persisted runtime evidence count=%d created=%d, want 8 records", len(persisted), len(created))
	}
	for index, wasCreated := range created {
		if !wasCreated {
			t.Fatalf("runtime evidence %d was unexpectedly treated as a replay", index)
		}
	}

	response := serve(NewHandler(repository, discardLogger()), http.MethodGet,
		"/api/v1/investigations/"+investigationID+"/timeline?source_type=RUNTIME&limit=20")
	if response.Code != http.StatusOK {
		t.Fatalf("timeline status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data store.InvestigationTimeline `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode runtime timeline: %v", err)
	}
	items := envelope.Data.Items
	if envelope.Data.InvestigationID != investigationID || envelope.Data.Total != 8 || len(items) != 8 || envelope.Data.HasMore {
		t.Fatalf("runtime timeline metadata = %+v", envelope.Data)
	}

	byTemplate := make(map[string]store.InvestigationTimelineItem, len(items))
	for _, item := range items {
		if item.SourceType != evidence.SourceRuntime || item.InvestigationID != investigationID {
			t.Fatalf("runtime timeline ownership/source = %s/%s", item.SourceType, item.InvestigationID)
		}
		if item.EntityID == nil || *item.EntityID == "" || item.IndependenceGroup == "" || item.CollectedAt == nil || !item.CollectedAt.Equal(collectedAt) {
			t.Fatalf("runtime timeline evidence lost entity, independence or collection metadata: %+v", item)
		}
		if !item.ObservedStart.Equal(start) || !item.ObservedEnd.Equal(end) {
			t.Fatalf("runtime timeline window = %s..%s", item.ObservedStart, item.ObservedEnd)
		}
		var parameters struct {
			TemplateID string `json:"template_id"`
		}
		if err := json.Unmarshal(item.QueryParameters, &parameters); err != nil || parameters.TemplateID == "" {
			t.Fatalf("runtime query parameters = %s (err=%v)", item.QueryParameters, err)
		}
		byTemplate[parameters.TemplateID] = item
	}
	for _, templateID := range []string{
		"prometheus.runtime.host.cpu.v1", "prometheus.runtime.host.memory_available.v1", "prometheus.runtime.host.load.v1",
		"prometheus.runtime.container.cpu.v1", "prometheus.runtime.container.memory.v1", "prometheus.runtime.container.oom_events.v1",
		"prometheus.runtime.container.start_time.v1", "loki.container.restarts.v1",
	} {
		if _, exists := byTemplate[templateID]; !exists {
			t.Errorf("runtime timeline is missing template %q", templateID)
		}
	}
	if len(byTemplate) != 8 {
		t.Fatalf("runtime timeline has %d distinct templates, want 8", len(byTemplate))
	}

	hostCPU := byTemplate["prometheus.runtime.host.cpu.v1"]
	if hostCPU.EntityType != "HOST" || hostCPU.EntityID == nil || *hostCPU.EntityID != "host-a" || hostCPU.RawReference != prometheusReference || !strings.Contains(string(hostCPU.ValueSummary), "0.4") {
		t.Errorf("host Evidence was not preserved by timeline API: %+v", hostCPU)
	}
	containerMemory := byTemplate["prometheus.runtime.container.memory.v1"]
	var containerSummary struct {
		Measurements []struct {
			EntityType     string `json:"entity_type"`
			EntityID       string `json:"entity_id"`
			MappingStatus  string `json:"mapping_status"`
			MappingVersion int    `json:"mapping_version"`
		} `json:"measurements"`
	}
	if err := json.Unmarshal(containerMemory.ValueSummary, &containerSummary); err != nil {
		t.Fatalf("decode container runtime summary: %v", err)
	}
	if containerMemory.EntityType != "HOST" || containerMemory.EntityID == nil || *containerMemory.EntityID != "host-a" ||
		containerMemory.Completeness != evidence.CompletenessPartial || len(containerSummary.Measurements) != 1 ||
		containerSummary.Measurements[0].EntityType != "CONTAINER" || containerSummary.Measurements[0].EntityID != "opaque-cgroup-a" ||
		containerSummary.Measurements[0].MappingStatus != "explicit_mapping" || containerSummary.Measurements[0].MappingVersion != 3 {
		t.Errorf("container Evidence identity/completeness = %+v, summary=%+v", containerMemory, containerSummary)
	}
	lifecycle := byTemplate["loki.container.restarts.v1"]
	if lifecycle.RawReference != lokiReference || !strings.Contains(string(lifecycle.ValueSummary), "unverified_log_match") || !strings.Contains(string(lifecycle.ValueSummary), "container restart observed") || !strings.Contains(string(lifecycle.ValueSummary), "healthy_peer_evidence_unavailable") {
		t.Errorf("lifecycle Evidence or collection gap was not preserved: %+v", lifecycle)
	}
}
