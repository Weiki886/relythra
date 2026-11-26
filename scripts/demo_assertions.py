"""Pure assertions shared by the disposable demo smoke and its unit tests."""

import math

PROMETHEUS_LATENCY_TEMPLATE = "prometheus.service.latency.v1"


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
