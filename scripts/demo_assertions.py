"""Pure assertions shared by the disposable demo smoke and its unit tests."""


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
