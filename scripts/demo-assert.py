#!/usr/bin/env python3
"""Assertions for the disposable demo stack; only reads local endpoints."""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from demo_assertions import assert_finite_latency_response, assert_loki_evidence_timeline, assert_prometheus_evidence_timeline, loki_mapping_payload, prometheus_mapping_payload


def check_config(path):
    with open(path, encoding="utf-8") as source:
        config = json.load(source)
    for name, service in config["services"].items():
        assert service.get("mem_limit") and service.get("cpus") and service.get("pids_limit"), name
        if name != "migrate":
            assert service.get("healthcheck"), name
        assert not service.get("privileged"), name
        if service.get("ports"):
            assert any(not config["networks"][network].get("internal", False) for network in service["networks"]), (name, "published ports require an ingress network")
        for port in service.get("ports", []):
            assert port.get("host_ip") == "127.0.0.1", (name, port)
        for mount in service.get("volumes", []):
            assert "docker.sock" not in mount.get("source", ""), (name, mount)
            assert mount.get("source") != "/", (name, "host root can indirectly expose runtime sockets")
            if mount["type"] == "bind":
                assert mount.get("read_only"), (name, mount)
    assert not config["services"]["demo-postgres"].get("ports")
    print("Compose boundaries: health, limits, loopback, mounts and socket isolation verified")


def http(port, path, authorized=False, method="GET", admin=False, data=None):
    headers = {}
    if authorized:
        with open(os.environ["DEMO_OBSERVABILITY_TOKEN_FILE"], encoding="utf-8") as secret:
            headers["Authorization"] = "Bearer " + secret.read().strip()
    if admin:
        with open(os.environ["DEMO_GRAFANA_PASSWORD_FILE"], encoding="utf-8") as secret:
            credentials = "admin:" + secret.read().strip()
        headers["Authorization"] = "Basic " + base64.b64encode(credentials.encode()).decode()
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            return response.status, response.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as error:
        return error.code, error.read(4096)


def eventually(assertion, timeout=100, interval=2):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            assertion()
            return
        except (AssertionError, urllib.error.URLError, TimeoutError, ConnectionError) as error:
            last = error
            time.sleep(interval)
    raise AssertionError(f"Timed out waiting for observable condition: {last}")


def recovered():
    assert http(28080, "/health/ready")[0] == 200, "control API readiness"
    status, raw = http(28090, "/orders")
    assert status == 200, ("orders", status)
    assert json.loads(raw)["available"] == 42, "seed data"


def healthy():
    eventually(recovered)
    for _ in range(5):
        assert http(28090, "/orders")[0] == 200
    assert http(29090, "/api/v1/query")[0] == 401, "metrics requires independent token"
    assert http(23100, "/loki/api/v1/labels")[0] == 401, "logs require independent token"
    for port, path in [(29090, "/api/v1/admin/tsdb/delete_series"), (29090, "/-/reload"), (23100, "/loki/api/v1/push")]:
        assert http(port, path, True, "POST")[0] == 403, ("write allowed", path)
        assert http(port, path, True)[0] == 403, ("unregistered path allowed", path)
    for path in ("/loki/api/v1/query", "/loki/api/v1/labels", "/ready"):
        assert http(23100, path, True, "POST")[0] == 403, ("unregistered POST allowed", path)
    assert http(23100, "/loki/api/v1/query_range", method="POST")[0] == 401, "Loki POST requires token"
    assert http(23100, "/loki/api/v1/query_range", True, "DELETE")[0] == 403, "Loki DELETE allowed"
    assert http(28090, "/internal/test/slow-query")[0] == 404, "faults must default off"

    def samples():
        status, raw = http(29090, "/api/v1/targets", True)
        assert status == 200, ("targets", status, raw[:100])
        targets = json.loads(raw)["data"]["activeTargets"]
        assert len(targets) == 6 and all(t["health"] == "up" for t in targets), [(t["labels"].get("job"), t["health"], t.get("lastError")) for t in targets]
        for query in ['demo_http_request_duration_seconds_count{service="orders"}', 'node_memory_MemAvailable_bytes', 'container_memory_working_set_bytes{id!="/"}', 'relythra_worker_heartbeat_timestamp_seconds', 'demo_service_info']:
            status, raw = http(29090, "/api/v1/query?" + urllib.parse.urlencode({"query": query}), True)
            result = json.loads(raw)["data"]["result"]
            assert status == 200 and result, ("missing sample", query)
    eventually(samples)

    _, identities_raw = http(29090, "/api/v1/query?query=demo_service_info", True)
    identities = {sample["metric"]["service"]: sample["metric"]["container"] for sample in json.loads(identities_raw)["data"]["result"]}
    assert set(identities) == {"orders", "inventory"}, "Explicit instance identities"

    def logs():
        status, raw = http(23100, "/loki/api/v1/query_range?" + urllib.parse.urlencode({"query": '{project="relythra-demo",env="demo"}', "limit": 10}), True)
        assert status == 200, ("loki", status, raw[:200])
        result = json.loads(raw)["data"]["result"]
        assert result, "Loki has no business logs"
        seen = set()
        for stream in result:
            labels = stream["stream"]
            seen.add(labels["service"])
            assert labels["container"] == identities[labels["service"]], "metrics/log instance identity mismatch"
            for key in ["project", "service", "env", "host", "container", "runtime_type", "release"]:
                assert labels.get(key), ("missing log label", key)
            for _, line in stream["values"]:
                assert json.loads(line)["msg"] == "request completed"
        assert seen == {"orders", "inventory"}, seen
    eventually(logs)
    eventually(loki_post_query_probe)
    def grafana_provisioned():
        status, raw = http(23001, "/api/dashboards/uid/relythra-demo")
        assert status == 200 and len(json.loads(raw)["dashboard"]["panels"]) == 6, "Grafana dashboard"
        status, raw = http(23001, "/api/datasources")
        assert status == 200 and len(json.loads(raw)) == 2, "Grafana datasources"
        assert b"secureJsonData" not in raw and b"Bearer " not in raw, "Grafana exposed credentials"
        status, raw = http(23001, "/api/v1/provisioning/alert-rules", admin=True)
        assert status == 200 and any(rule["uid"] == "demo-target-down" for rule in json.loads(raw)), "Grafana alert provisioning"
    eventually(grafana_provisioned)
    assert http(23001, "/api/dashboards/db", method="POST")[0] in (401, 403), "Viewer can write dashboards"
    print("Real telemetry verified: six healthy scrape targets, business/node/cgroup/worker samples, labeled JSON logs and Grafana dashboard")


def loki_post_query_probe():
    data = urllib.parse.urlencode({
        "query": '{service="inventory",env="demo"} |~ "(?i)(slow query|query_id|duration_ms)"',
        "limit": 10,
    }).encode()
    status, raw = http(23100, "/loki/api/v1/query_range", True, method="POST", data=data)
    assert status == 200, ("Loki POST query", status)
    response = json.loads(raw)
    assert response.get("status") == "success" and response.get("data", {}).get("result"), "Loki POST query has no logs"


def configure_mapping(mapping, source_name):
    with open(os.environ["RELYTHRA_MANAGEMENT_TOKEN_FILE"], encoding="utf-8") as secret:
        token = secret.read().strip()
    payload = json.dumps(mapping).encode("utf-8")
    request = urllib.request.Request(
        "http://127.0.0.1:28080/api/v1/data-source-mappings",
        data=payload,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            status, raw = response.status, response.read(64 * 1024)
    except urllib.error.HTTPError as error:
        raise AssertionError(f"{source_name} mapping API returned HTTP {error.code}") from None
    assert status == 201, (f"{source_name} mapping create", status)
    assert token.encode() not in raw, "mapping response exposed the management token"
    response = json.loads(raw)
    assert response.get("data", {}).get("secret_status") == "configured", f"{source_name} SecretRef was not resolved"
    print(f"Isolated Inventory {source_name} mapping created through the authenticated management API")


def prometheus_evidence(investigation_id):
    path = f"/api/v1/investigations/{investigation_id}/timeline?" + urllib.parse.urlencode({
        "source_type": "PROMETHEUS",
        "limit": 100,
    })

    def collected():
        status, raw = http(28080, path)
        assert status == 200, ("Prometheus timeline read", status, raw[:200])
        envelope = json.loads(raw)
        assert envelope.get("data") is not None, "Prometheus timeline response has no data"
        item = assert_prometheus_evidence_timeline(envelope["data"], investigation_id)
        assert item.get("id"), "Prometheus Evidence has no ID"
        status, raw = http(28080, f"/api/v1/evidence/{item['id']}")
        assert status == 200 and json.loads(raw).get("data", {}).get("id") == item["id"], "Prometheus Evidence deep link"

    eventually(collected, timeout=180)
    print(f"Worker Prometheus latency Evidence verified for Investigation {investigation_id}")


def loki_evidence(investigation_id, service_id):
    path = f"/api/v1/investigations/{investigation_id}/timeline?" + urllib.parse.urlencode({
        "source_type": "LOKI",
        "limit": 100,
    })

    def collected():
        status, raw = http(28080, path)
        assert status == 200, ("Loki timeline read", status)
        timeline = json.loads(raw).get("data")
        assert isinstance(timeline, dict), "Loki timeline response has no data"
        item = assert_loki_evidence_timeline(timeline, investigation_id, service_id)
        assert item.get("id"), "Loki Evidence has no ID"
        source = urllib.parse.urlparse(item.get("raw_reference", ""))
        assert source.hostname == "observability-gateway" and source.port == 3100 and source.path == "/loki/api/v1/query_range", "Loki original query reference"
        status, raw = http(28080, f"/api/v1/evidence/{item['id']}")
        evidence = json.loads(raw).get("data") if status == 200 else None
        assert isinstance(evidence, dict) and evidence.get("id") == item["id"], "Loki Evidence deep link"
        assert evidence.get("investigation_id") == investigation_id, "Loki deep link investigation ownership"
        assert_loki_evidence_timeline({"investigation_id": investigation_id, "items": [evidence]}, investigation_id, service_id)

    eventually(collected, timeout=180)
    print(f"Worker Loki request log Evidence verified for Investigation {investigation_id}")


def prime_prometheus_latency():
    query = 'histogram_quantile(0.95, sum by (le, route) (rate(demo_http_request_duration_seconds_bucket{service="inventory",env="demo"}[5m])))'

    def finite_latency():
        status, raw = http(28090, "/orders")
        assert status == 200 and json.loads(raw).get("available") == 42, ("latency priming request", status, raw[:200])
        # Match collectionWindow and collectionQueryStep in internal/worker/collection.go.
        # On a fresh stack the latest evaluation is one minute before this end.
        end = time.time()
        params = {"query": query, "start": end - 300, "end": end, "step": 120}
        status, raw = http(29090, "/api/v1/query_range?" + urllib.parse.urlencode(params), True)
        assert status == 200, ("Prometheus latency range query", status, raw[:200])
        assert_finite_latency_response(json.loads(raw))

    eventually(finite_latency, timeout=180, interval=6)
    print("Inventory latency histogram has a finite Prometheus sample on the Worker range-query grid")


def grafana_delivery(investigation_id, expected_status):
    def delivered():
        status, raw = http(28080, f"/api/v1/investigations/{investigation_id}")
        assert status == 200, ("Investigation read", status)
        context = json.loads(raw)["data"]
        assert context["project"]["slug"] == "relythra-demo", "Project mapping"
        assert context["service"]["slug"] == "inventory", "Service mapping"
        assert context["environment"] == "demo", "Environment mapping"
        assert context["alert"]["status"] == expected_status, ("Alert transition", context["alert"]["status"])
        alert_id = context["alert"]["id"]
        status, raw = http(28080, f"/api/v1/investigations/{investigation_id}/timeline")
        assert status == 200, ("Evidence timeline read", status)
        observations = [item for item in json.loads(raw)["data"]["items"] if item["source_type"] == "GRAFANA" and item["value_summary"]["alert_id"] == alert_id]
        transitions = {item["value_summary"]["status"] for item in observations}
        required = {"FIRING", expected_status}
        assert required <= transitions, ("Missing Grafana evidence transition", transitions)
        for item in observations:
            assert item["raw_reference"].startswith("http://127.0.0.1:23001/alerting/"), "Grafana source link"
            status, raw = http(28080, f"/api/v1/evidence/{item['id']}")
            assert status == 200 and json.loads(raw)["data"]["id"] == item["id"], "Evidence deep link"
    eventually(delivered, timeout=120)
    print(f"Grafana signed {expected_status} delivery and Evidence verified for Investigation {investigation_id}")


def prometheus_scalar(query):
    status, raw = http(29090, "/api/v1/query?" + urllib.parse.urlencode({"query": query}), True)
    assert status == 200, ("Prometheus query", query, status)
    result = json.loads(raw)["data"]["result"]
    return float(result[0]["value"][1]) if result else 0.0


def inventory_request_logs(release, started_ns, slow):
    selector = '{project="relythra-demo",service="inventory",env="demo",release="' + release + '"} |= "request completed"'
    status, raw = http(23100, "/loki/api/v1/query_range?" + urllib.parse.urlencode({
        "query": selector,
        "limit": 100,
        "direction": "backward",
        "start": str(started_ns),
        "end": str(time.time_ns()),
    }), True)
    assert status == 200, ("Loki slow SQL query", status, raw[:200])
    result = json.loads(raw)["data"]["result"]
    entries = [
        json.loads(line)
        for stream in result
        for _, line in stream["values"]
        if json.loads(line).get("route") == "/stock"
    ]
    if slow:
        assert any(float(entry.get("duration_ms", 0)) >= 150 for entry in entries), ("slow SQL log missing", entries)
    else:
        assert any(float(entry.get("duration_ms", 10000)) < 150 for entry in entries), ("recovered SQL log missing", entries)


def slow_sql_fault():
    total_query = 'demo_http_request_duration_seconds_bucket{service="orders",route="/orders",le="+Inf"}'
    fast_query = 'demo_http_request_duration_seconds_bucket{service="orders",route="/orders",le="0.1"}'
    before_total = prometheus_scalar(total_query)
    before_fast = prometheus_scalar(fast_query)
    started_ns = time.time_ns()
    durations = []
    for _ in range(8):
        started = time.monotonic()
        status, raw = http(28090, "/orders")
        durations.append(time.monotonic() - started)
        assert status == 200 and json.loads(raw)["available"] == 42, ("slow SQL orders request", status, raw[:200])
    assert min(durations) >= 0.15, ("orders path did not observe the slow SQL fault", durations)

    def fault_metrics():
        total = prometheus_scalar(total_query)
        fast = prometheus_scalar(fast_query)
        assert total >= before_total + 8, ("orders request histogram did not record all fault requests", before_total, total)
        assert fast == before_fast, ("fault requests unexpectedly landed in the <=100ms bucket", before_fast, fast)

    eventually(fault_metrics)
    eventually(lambda: inventory_request_logs("slow-sql-fault", started_ns, True))
    print("Slow SQL fault verified: orders latency histogram and inventory query log show the same workload")


def slow_sql_recovered():
    total_query = 'demo_http_request_duration_seconds_bucket{service="orders",route="/orders",le="+Inf"}'
    fast_query = 'demo_http_request_duration_seconds_bucket{service="orders",route="/orders",le="0.1"}'
    before_total = prometheus_scalar(total_query)
    before_fast = prometheus_scalar(fast_query)
    started_ns = time.time_ns()
    for _ in range(8):
        status, raw = http(28090, "/orders")
        assert status == 200 and json.loads(raw)["available"] == 42, ("recovered orders request", status, raw[:200])

    def recovered_metrics():
        total = prometheus_scalar(total_query)
        fast = prometheus_scalar(fast_query)
        assert total >= before_total + 8, ("orders recovery histogram is incomplete", before_total, total)
        assert fast >= before_fast + 8, ("orders latency did not return to the <=100ms bucket", before_fast, fast)

    eventually(recovered_metrics)
    eventually(lambda: inventory_request_logs("baseline", started_ns, False))
    print("Slow SQL recovery verified: orders latency and inventory query logs returned to baseline")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "config":
        check_config(sys.argv[2])
    elif mode == "healthy":
        healthy()
    elif mode == "dependency-down":
        assert http(28090, "/health/ready")[0] == 503
        assert http(28090, "/orders")[0] == 503
        assert http(28090, "/health/live")[0] == 200
        assert http(28080, "/health/ready")[0] == 200, "demo failure reached control plane"
        print("Demo database loss: orders not ready, still live; control plane healthy")
    elif mode == "recovered":
        eventually(recovered)
    elif mode == "configure-prometheus-mapping":
        configure_mapping(prometheus_mapping_payload(sys.argv[2], sys.argv[3]), "Prometheus")
    elif mode == "configure-loki-mapping":
        configure_mapping(loki_mapping_payload(sys.argv[2], sys.argv[3]), "Loki")
    elif mode == "loki-evidence":
        loki_evidence(sys.argv[2], sys.argv[3])
    elif mode == "prometheus-evidence":
        prometheus_evidence(sys.argv[2])
    elif mode == "prime-prometheus-latency":
        prime_prometheus_latency()
    elif mode == "grafana-delivery":
        grafana_delivery(sys.argv[2], sys.argv[3])
    elif mode == "slow-sql-fault":
        slow_sql_fault()
    elif mode == "slow-sql-recovered":
        slow_sql_recovered()
    else:
        raise ValueError("Unknown assertion mode")
