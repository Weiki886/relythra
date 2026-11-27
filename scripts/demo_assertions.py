"""Pure assertions shared by the disposable demo smoke and its unit tests."""

import json
import math
import urllib.parse

PROMETHEUS_LATENCY_TEMPLATE = "prometheus.service.latency.v1"
LOKI_REQUEST_TEMPLATE = "loki.service.slow_queries.v1"
RUNTIME_EVIDENCE_TEMPLATES = (
    "prometheus.runtime.host.cpu.v1",
    "prometheus.runtime.host.memory_available.v1",
    "prometheus.runtime.host.load.v1",
    "prometheus.runtime.container.cpu.v1",
    "prometheus.runtime.container.memory.v1",
    "prometheus.runtime.container.oom_events.v1",
    "prometheus.runtime.container.start_time.v1",
    "loki.container.restarts.v1",
)


def prometheus_mapping_payload(project_id, service_id):
    return {
        "project_id": project_id,
        "service_id": service_id,
        "environment": "demo",
        "source_type": "PROMETHEUS",
        "public_settings": {"endpoint": "http://observability-gateway:9090"},
        "template_ids": [PROMETHEUS_LATENCY_TEMPLATE],
        "secret_ref": "file:/run/relythra-secrets/observability_token",
    }


def assert_prometheus_evidence_timeline(timeline, investigation_id):
    assert timeline.get("investigation_id") == investigation_id, (
        "investigation_id", timeline.get("investigation_id"), investigation_id
    )
    items = timeline.get("items")
    assert isinstance(items, list), "timeline items are missing"
    evidence_items = [
        item for item in items
        if isinstance(item, dict)
        and item.get("source_type") == "PROMETHEUS"
        and isinstance(item.get("query_parameters"), dict)
        and item["query_parameters"].get("template_id") == PROMETHEUS_LATENCY_TEMPLATE
    ]
    assert evidence_items, f"missing latency template {PROMETHEUS_LATENCY_TEMPLATE}"
    for item in evidence_items:
        summary = item.get("value_summary")
        series = summary.get("series") if isinstance(summary, dict) else None
        if isinstance(series, list) and any(
            isinstance(entry, dict)
            and isinstance(entry.get("samples"), list)
            and any(
                isinstance(sample, dict)
                and isinstance(sample.get("timestamp"), str)
                and bool(sample["timestamp"])
                and isinstance(sample.get("value"), (int, float))
                and not isinstance(sample["value"], bool)
                for sample in entry["samples"]
            )
            for entry in series
        ):
            return item
    raise AssertionError("Prometheus latency Evidence has no samples")


def assert_finite_latency_response(response):
    data = response.get("data", {}) if response.get("status") == "success" else {}
    result = data.get("result") if data.get("resultType") == "matrix" else None
    if isinstance(result, list):
        for series in result:
            values = series.get("values") if isinstance(series, dict) else None
            if not isinstance(values, list):
                continue
            for sample in values:
                if not isinstance(sample, list) or len(sample) < 2:
                    continue
                try:
                    latency = float(sample[1])
                except (TypeError, ValueError):
                    continue
                if math.isfinite(latency) and latency > 0:
                    return latency
    raise AssertionError("Prometheus range query has no finite positive latency")


def loki_mapping_payload(project_id, service_id):
    return {
        "project_id": project_id,
        "service_id": service_id,
        "environment": "demo",
        "source_type": "LOKI",
        "public_settings": {"endpoint": "http://observability-gateway:3100"},
        "template_ids": [LOKI_REQUEST_TEMPLATE],
        "secret_ref": "file:/run/relythra-secrets/observability_token",
    }


def runtime_mapping_payload(project_id, service_id):
    return {
        "project_id": project_id,
        "service_id": service_id,
        "environment": "demo",
        "source_type": "RUNTIME",
        "runtime_type": "docker-compose",
        "public_settings": {
            "endpoint": "http://observability-gateway:9090",
            "runtime_labels": {
                "project": "relythra-demo",
                "service": "inventory",
                "env": "demo",
                "host_id": "demo-host",
                "container_id": "unmapped",
            },
            "container_mappings": [],
        },
        "template_ids": ["runtime.containers.v1", "runtime.host.v1", "runtime.events.v1"],
    }


def assert_runtime_evidence_timeline(timeline, investigation_id, host_id):
    assert timeline.get("investigation_id") == investigation_id, "Runtime investigation ownership"
    items = timeline.get("items")
    assert isinstance(items, list), "Runtime timeline items are missing"
    evidence_by_template = {}
    for item in items:
        if not isinstance(item, dict) or item.get("source_type") != "RUNTIME":
            continue
        parameters = item.get("query_parameters")
        assert isinstance(parameters, dict), "Runtime query parameters are missing"
        template = parameters.get("template_id")
        assert template in RUNTIME_EVIDENCE_TEMPLATES, "Runtime Evidence has an unexpected template"
        assert template not in evidence_by_template, f"duplicate Runtime Evidence for {template}"
        assert item.get("id"), f"Runtime Evidence ID is missing for {template}"
        assert item.get("entity_type") == "HOST" and item.get("entity_id") == host_id, "Runtime Evidence host ownership"
        assert item.get("completeness") in ("PARTIAL", "MISSING"), "Runtime Evidence overstates collection completeness"
        assert parameters.get("runtime") == "docker-compose", "Runtime type"
        assert parameters.get("service") == "inventory" and parameters.get("environment") == "demo", "Runtime service scope"
        assert parameters.get("host_id") == host_id and parameters.get("template_version") == 1, "Runtime host/template version"
        summary = item.get("value_summary")
        assert isinstance(summary, dict), "Runtime Evidence summary is missing"
        assert summary.get("partial") is True, "Runtime Evidence omitted its partial-coverage marker"
        assert isinstance(summary.get("gaps"), list) and summary["gaps"], "Runtime Evidence omitted collection gaps"
        assert isinstance(summary.get("measurements"), list), "Runtime measurements are missing"
        assert isinstance(summary.get("events"), list), "Runtime lifecycle events are missing"
        reference_available = summary.get("source_reference_available")
        raw_reference = item.get("raw_reference") or ""
        assert isinstance(reference_available, bool) and reference_available == bool(raw_reference), "Runtime source reference metadata"
        if raw_reference:
            reference = urllib.parse.urlparse(raw_reference)
            allowed_sources = {
                ("observability-gateway", 9090, "/api/v1/query_range"),
                ("observability-gateway", 3100, "/loki/api/v1/query_range"),
            }
            assert (reference.hostname, reference.port, reference.path) in allowed_sources, "Runtime original source reference"
            assert reference.scheme == "http" and reference.username is None and reference.password is None, "Runtime source reference is unsafe"
        evidence_by_template[template] = item
    assert set(evidence_by_template) == set(RUNTIME_EVIDENCE_TEMPLATES), (
        "Runtime Evidence template coverage", sorted(evidence_by_template)
    )
    assert_runtime_required_memory_samples(evidence_by_template, host_id)
    return evidence_by_template


def assert_runtime_required_memory_samples(evidence_by_template, host_id):
    required = (
        ("prometheus.runtime.host.memory_available.v1", "HOST"),
        ("prometheus.runtime.container.memory.v1", "CONTAINER"),
    )
    for template, entity_type in required:
        item = evidence_by_template[template]
        observations = item["value_summary"]["measurements"]
        if entity_type == "HOST":
            matching = [observation for observation in observations
                        if isinstance(observation, dict) and observation.get("entity_type") == "HOST"
                        and observation.get("entity_id") == host_id and observation.get("host_id") == host_id]
        else:
            matching = [observation for observation in observations
                        if isinstance(observation, dict) and observation.get("entity_type") == "CONTAINER"
                        and observation.get("host_id") == host_id and observation.get("mapping_status") == "raw_cgroup_only"]
            assert all(not observation.get("service") for observation in matching), "Runtime inferred a service for an unmapped cgroup"

        has_samples = False
        for observation in matching:
            measurement = observation.get("measurement")
            assert isinstance(measurement, dict), f"Runtime {template} measurement is missing"
            samples = measurement.get("samples")
            if not isinstance(samples, list) or not samples:
                continue
            source_reference = measurement.get("source_reference")
            assert isinstance(source_reference, str) and source_reference, f"Runtime {template} sample source reference is missing"
            reference = urllib.parse.urlparse(source_reference)
            assert (reference.scheme, reference.hostname, reference.port, reference.path) == (
                "http", "observability-gateway", 9090, "/api/v1/query_range",
            ), f"Runtime {template} Prometheus source reference"
            assert reference.username is None and reference.password is None, f"Runtime {template} source reference contains credentials"
            for sample in samples:
                assert isinstance(sample, dict) and isinstance(sample.get("timestamp"), str) and sample["timestamp"], (
                    f"Runtime {template} sample timestamp is missing"
                )
                value = sample.get("value")
                assert isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0, (
                    f"Runtime {template} sample must be finite and non-negative"
                )
            has_samples = True
        assert has_samples, f"Runtime {template} has no collected sample"


def assert_loki_evidence_timeline(timeline, investigation_id, service_id):
    assert timeline.get("investigation_id") == investigation_id, "Loki investigation ownership"
    items = timeline.get("items")
    assert isinstance(items, list), "Loki timeline items are missing"
    evidence_items = [
        item for item in items
        if isinstance(item, dict)
        and item.get("source_type") == "LOKI"
        and isinstance(item.get("query_parameters"), dict)
        and item["query_parameters"].get("template_id") == LOKI_REQUEST_TEMPLATE
    ]
    assert evidence_items, "Loki request template Evidence is missing"
    for item in evidence_items:
        assert item.get("entity_type") == "SERVICE" and item.get("entity_id") == service_id, "Loki service ownership"
        assert item.get("completeness") in ("COMPLETE", "PARTIAL"), "Loki Evidence is missing"
        summary = item.get("value_summary")
        entries = summary.get("entries") if isinstance(summary, dict) else None
        assert isinstance(entries, list) and entries, "Loki Evidence has no entries"
        for entry in entries:
            assert isinstance(entry, dict) and entry.get("timestamp"), "Loki entry has no timestamp"
            labels = entry.get("labels")
            assert isinstance(labels, dict) and all(
                labels.get(key) == value
                for key, value in {"project": "relythra-demo", "service": "inventory", "env": "demo"}.items()
            ), "Loki entry labels do not match the demo service"
            line = entry.get("line")
            assert isinstance(line, dict) and line.get("trust") == "untrusted_data" and line.get("source") == "loki", "Loki trust metadata"
            try:
                log = json.loads(line.get("content"))
            except (ValueError, TypeError):
                continue
            if not isinstance(log, dict) or log.get("msg") != "request completed" or log.get("route") != "/stock":
                continue
            duration = log.get("duration_ms")
            if isinstance(duration, (int, float)) and not isinstance(duration, bool) and math.isfinite(duration) and duration >= 0:
                return item
    raise AssertionError("Loki Evidence has no Inventory stock request log with finite duration")
