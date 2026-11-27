import base64
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from demo_artifacts import MAX_CAPTURE_BYTES, capture_compose, collect, collect_http, compose_command, read_secrets, redact, remove_partial_secret, safe_compose_output, write_capture
from demo_assertions import (
    RUNTIME_EVIDENCE_TEMPLATES,
    assert_finite_latency_response,
    assert_loki_evidence_timeline,
    assert_prometheus_evidence_timeline,
    assert_runtime_evidence_timeline,
    loki_mapping_payload,
    prometheus_mapping_payload,
    runtime_mapping_payload,
)

ROOT = Path(__file__).resolve().parent.parent


class FakeResponse:
    status = 200

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return self.body[:_limit]


def prometheus_timeline(investigation_id="demo-investigation"):
    return {
        "investigation_id": investigation_id,
        "items": [{
            "source_type": "PROMETHEUS",
            "query_parameters": {"template_id": "prometheus.service.latency.v1"},
            "value_summary": {"series": [{"samples": [{"timestamp": "2026-11-26T00:00:00Z", "value": 0.42}]}]},
        }],
    }


class DemoPrometheusEvidenceTests(unittest.TestCase):
    def test_accepts_finite_positive_prometheus_range_latency(self):
        response = {"status": "success", "data": {"resultType": "matrix", "result": [
            {"values": [[1795651080, "NaN"], [1795651200, "0.125"]]},
        ]}}
        self.assertEqual(assert_finite_latency_response(response), 0.125)

    def test_rejects_missing_nan_or_zero_range_latency_and_instant_results(self):
        responses = [
            {"status": "success", "data": {"resultType": "matrix", "result": []}},
            {"status": "success", "data": {"resultType": "matrix", "result": [{"values": []}]}},
            {"status": "success", "data": {"resultType": "vector", "result": [{"value": [1795651200, "0.125"]}]}},
        ]
        for value in ("NaN", "+Inf", "-Inf", "0", "-1", "invalid", None):
            responses.append({"status": "success", "data": {"resultType": "matrix", "result": [
                {"values": [[1795651200, value]]},
            ]}})
        for response in responses:
            with self.subTest(response=response), self.assertRaisesRegex(AssertionError, "finite positive latency"):
                assert_finite_latency_response(response)

    def run_latency_priming(self, range_ready):
        spec = importlib.util.spec_from_file_location("demo_smoke_assert", ROOT / "scripts/demo-assert.py")
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        clock = [1000.0]
        requests = []
        range_queries = []

        def sleep(seconds):
            clock[0] += seconds

        def http(port, path, authorized=False):
            if port == 28090:
                self.assertEqual(path, "/orders")
                requests.append(clock[0])
                return 200, b'{"available": 42}'
            self.assertEqual(port, 29090)
            self.assertTrue(authorized)
            url = smoke.urllib.parse.urlparse(path)
            params = smoke.urllib.parse.parse_qs(url.query)
            if url.path == "/api/v1/query":
                # The old instant check passes as soon as traffic spans two scrapes.
                return 200, json.dumps({"status": "success", "data": {"resultType": "vector", "result": [
                    {"value": [clock[0], "0.125"]},
                ]}}).encode()
            self.assertEqual(url.path, "/api/v1/query_range")
            start, end, step = (float(params[key][0]) for key in ("start", "end", "step"))
            self.assertEqual(end, clock[0])
            self.assertEqual(end - start, 300)
            self.assertEqual(step, 120)
            self.assertIn('service="inventory",env="demo"', params["query"][0])
            self.assertIn("[5m]", params["query"][0])
            range_queries.append(clock[0])
            # Finite histograms begin after two 5s scrapes. Worker evaluations
            # at end-300, end-180 and end-60 initially all precede that data.
            values = [[start + index * step, "0.125" if range_ready and start + index * step >= 1010 else "NaN"]
                      for index in range(3)]
            return 200, json.dumps({"status": "success", "data": {"resultType": "matrix", "result": [
                {"values": values},
            ]}}).encode()

        with patch.object(smoke, "http", side_effect=http), \
             patch.object(smoke.time, "time", side_effect=lambda: clock[0]), \
             patch.object(smoke.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(smoke.time, "sleep", side_effect=sleep), \
             patch("builtins.print"):
            if range_ready:
                smoke.prime_prometheus_latency()
            else:
                with self.assertRaisesRegex(AssertionError, "Timed out"):
                    smoke.prime_prometheus_latency()
        return clock[0], requests, range_queries

    def test_priming_keeps_traffic_until_worker_range_grid_has_finite_data(self):
        finished, requests, queries = self.run_latency_priming(range_ready=True)
        self.assertGreaterEqual(finished, 1070)
        self.assertGreater(len(requests), 3)
        self.assertGreater(len(queries), 1)
        self.assertLessEqual(max(b - a for a, b in zip(requests, requests[1:])), 6)
        self.assertEqual(requests[-1], queries[-1])

    def test_priming_times_out_when_worker_range_grid_stays_empty(self):
        finished, requests, queries = self.run_latency_priming(range_ready=False)
        self.assertGreaterEqual(finished, 1180)
        self.assertLessEqual(finished, 1186)
        self.assertGreater(len(requests), 3)
        self.assertGreater(len(queries), 1)

    def test_mapping_is_scoped_to_demo_service_and_fixed_read_only_template(self):
        mapping = prometheus_mapping_payload("project-id", "service-id")
        self.assertEqual(mapping["project_id"], "project-id")
        self.assertEqual(mapping["service_id"], "service-id")
        self.assertEqual(mapping["environment"], "demo")
        self.assertEqual(mapping["source_type"], "PROMETHEUS")
        self.assertEqual(mapping["public_settings"]["endpoint"], "http://observability-gateway:9090")
        self.assertEqual(mapping["template_ids"], ["prometheus.service.latency.v1"])
        self.assertEqual(mapping["secret_ref"], "file:/run/relythra-secrets/observability_token")

    def test_accepts_populated_latency_evidence_for_requested_investigation(self):
        evidence = assert_prometheus_evidence_timeline(prometheus_timeline(), "demo-investigation")
        self.assertEqual(evidence["source_type"], "PROMETHEUS")
        self.assertEqual(evidence["query_parameters"]["template_id"], "prometheus.service.latency.v1")

    def test_rejects_evidence_from_another_investigation(self):
        with self.assertRaisesRegex(AssertionError, "investigation_id"):
            assert_prometheus_evidence_timeline(prometheus_timeline("other-investigation"), "demo-investigation")

    def test_rejects_missing_latency_template(self):
        timeline = prometheus_timeline()
        timeline["items"][0]["query_parameters"]["template_id"] = "prometheus.other.v1"
        with self.assertRaisesRegex(AssertionError, "latency template"):
            assert_prometheus_evidence_timeline(timeline, "demo-investigation")

    def test_rejects_empty_or_malformed_samples(self):
        for series in ([], [{"samples": []}], [{"samples": [{"timestamp": "", "value": "unknown"}]}]):
            with self.subTest(series=series), self.assertRaisesRegex(AssertionError, "samples"):
                timeline = prometheus_timeline()
                timeline["items"][0]["value_summary"]["series"] = series
                assert_prometheus_evidence_timeline(timeline, "demo-investigation")


def loki_timeline():
    return {
        "investigation_id": "demo-investigation",
        "items": [{
            "id": "loki-evidence",
            "source_type": "LOKI",
            "entity_type": "SERVICE",
            "entity_id": "inventory-id",
            "completeness": "PARTIAL",
            "query_parameters": {"template_id": "loki.service.slow_queries.v1"},
            "value_summary": {"entries": [{
                "timestamp": "2026-11-26T00:00:00Z",
                "labels": {"project": "relythra-demo", "service": "inventory", "env": "demo"},
                "line": {
                    "trust": "untrusted_data",
                    "source": "loki",
                    "content": json.dumps({"msg": "request completed", "route": "/stock", "duration_ms": 12.5}),
                },
            }]},
        }],
    }


class DemoLokiEvidenceTests(unittest.TestCase):
    def load_smoke(self):
        spec = importlib.util.spec_from_file_location("demo_loki_smoke_assert", ROOT / "scripts/demo-assert.py")
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        return smoke

    def test_loki_post_probe_uses_form_query_and_requires_nonempty_success(self):
        smoke = self.load_smoke()
        result = {"status": "success", "data": {"resultType": "streams", "result": [{"stream": {"service": "inventory"}, "values": [["1", "request"]]}]}}
        with patch.object(smoke, "http", return_value=(200, json.dumps(result).encode())) as call:
            smoke.loki_post_query_probe()
        args, kwargs = call.call_args
        self.assertEqual(args, (23100, "/loki/api/v1/query_range", True))
        self.assertEqual(kwargs["method"], "POST")
        params = smoke.urllib.parse.parse_qs(kwargs["data"].decode())
        self.assertIn('service="inventory",env="demo"', params["query"][0])
        self.assertEqual(params["limit"], ["10"])
        for status, response in ((403, b"denied"), (200, b'{"status":"success","data":{"result":[]}}')):
            with patch.object(smoke, "http", return_value=(status, response)), self.assertRaises(AssertionError):
                smoke.loki_post_query_probe()

    def test_mapping_is_created_through_authenticated_management_api(self):
        smoke = self.load_smoke()
        mapping = loki_mapping_payload("project-id", "inventory-id")
        response = FakeResponse(b'{"data":{"secret_status":"configured"}}')
        response.status = 201
        with tempfile.TemporaryDirectory() as directory:
            secret_path = Path(directory) / "management_token"
            secret_path.write_text("demo-management-canary")
            with patch.dict(os.environ, {"RELYTHRA_MANAGEMENT_TOKEN_FILE": str(secret_path)}), \
                 patch.object(smoke.urllib.request, "urlopen", return_value=response) as call, \
                 patch("builtins.print"):
                smoke.configure_mapping(mapping, "Loki")
            request = call.call_args.args[0]
            self.assertEqual(request.full_url, "http://127.0.0.1:28080/api/v1/data-source-mappings")
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.get_header("Authorization"), "Bearer demo-management-canary")
            self.assertEqual(json.loads(request.data), mapping)
            self.assertNotIn("demo-management-canary", request.data.decode())

    def test_loki_mode_reads_filtered_timeline_and_matching_evidence_link(self):
        self.run_loki_mode("demo-investigation")

    def test_loki_mode_rejects_deep_link_from_another_investigation(self):
        with self.assertRaisesRegex(AssertionError, "investigation ownership"):
            self.run_loki_mode("another-investigation")

    def run_loki_mode(self, deep_investigation):
        smoke = self.load_smoke()
        timeline = loki_timeline()
        item = timeline["items"][0]
        item["raw_reference"] = "http://observability-gateway:3100/loki/api/v1/query_range?query=demo"
        evidence = dict(item, investigation_id=deep_investigation)
        paths = []

        def http(port, path):
            self.assertEqual(port, 28080)
            paths.append(path)
            if path.startswith("/api/v1/investigations/"):
                params = smoke.urllib.parse.parse_qs(smoke.urllib.parse.urlparse(path).query)
                self.assertEqual(params, {"source_type": ["LOKI"], "limit": ["100"]})
                return 200, json.dumps({"data": timeline}).encode()
            self.assertEqual(path, "/api/v1/evidence/loki-evidence")
            return 200, json.dumps({"data": evidence}).encode()

        with patch.object(smoke, "http", side_effect=http), \
             patch.object(smoke, "eventually", side_effect=lambda check, timeout: check()), \
             patch("builtins.print"):
            smoke.loki_evidence("demo-investigation", "inventory-id")
        self.assertEqual(len(paths), 2)

    def test_mapping_uses_demo_scope_gateway_and_registered_template(self):
        self.assertEqual(loki_mapping_payload("project-id", "service-id"), {
            "project_id": "project-id", "service_id": "service-id", "environment": "demo",
            "source_type": "LOKI", "public_settings": {"endpoint": "http://observability-gateway:3100"},
            "template_ids": ["loki.service.slow_queries.v1"],
            "secret_ref": "file:/run/relythra-secrets/observability_token",
        })

    def test_accepts_real_inventory_request_evidence_including_partial(self):
        for completeness in ("COMPLETE", "PARTIAL"):
            timeline = loki_timeline()
            timeline["items"][0]["completeness"] = completeness
            item = assert_loki_evidence_timeline(timeline, "demo-investigation", "inventory-id")
            self.assertEqual(item["id"], "loki-evidence")

    def test_rejects_wrong_investigation_service_template_or_source(self):
        for field, value in (("entity_id", "orders-id"), ("entity_type", "HOST"),
                             ("source_type", "PROMETHEUS"), ("completeness", "MISSING")):
            with self.subTest(field=field):
                timeline = loki_timeline()
                timeline["items"][0][field] = value
                with self.assertRaises(AssertionError):
                    assert_loki_evidence_timeline(timeline, "demo-investigation", "inventory-id")
        timeline = loki_timeline()
        with self.assertRaises(AssertionError):
            assert_loki_evidence_timeline(timeline, "another-investigation", "inventory-id")
        timeline["items"][0]["query_parameters"]["template_id"] = "loki.service.errors.v1"
        with self.assertRaises(AssertionError):
            assert_loki_evidence_timeline(timeline, "demo-investigation", "inventory-id")

    def test_rejects_empty_entries_and_invalid_labels_or_trust(self):
        for field, value in (("labels", {"service": "orders", "env": "demo"}),
                             ("labels", {"service": "inventory", "env": "prod"}),
                             ("line", {"trust": "trusted", "source": "loki", "content": "request completed"}),
                             ("line", {"trust": "untrusted_data", "source": "github", "content": "request completed"})):
            with self.subTest(field=field, value=value):
                timeline = loki_timeline()
                timeline["items"][0]["value_summary"]["entries"][0][field] = value
                with self.assertRaises(AssertionError):
                    assert_loki_evidence_timeline(timeline, "demo-investigation", "inventory-id")
        for entries in (None, [], [None]):
            timeline = loki_timeline()
            timeline["items"][0]["value_summary"]["entries"] = entries
            with self.subTest(entries=entries), self.assertRaises(AssertionError):
                assert_loki_evidence_timeline(timeline, "demo-investigation", "inventory-id")

    def test_requires_stock_request_with_finite_nonnegative_duration(self):
        bad_logs = [None, "request completed", "[]", json.dumps({"route": "/health/ready", "duration_ms": 1})]
        for duration in (None, True, "12", -1, float("nan"), float("inf")):
            bad_logs.append(json.dumps({"msg": "request completed", "route": "/stock", "duration_ms": duration}))
        for content in bad_logs:
            timeline = loki_timeline()
            timeline["items"][0]["value_summary"]["entries"][0]["line"]["content"] = content
            with self.subTest(content=content), self.assertRaises(AssertionError):
                assert_loki_evidence_timeline(timeline, "demo-investigation", "inventory-id")


def runtime_timeline():
    host_memory_template = "prometheus.runtime.host.memory_available.v1"
    container_memory_template = "prometheus.runtime.container.memory.v1"
    return {
        "investigation_id": "demo-investigation",
        "items": [runtime_item(template, host_memory_template, container_memory_template)
                  for template in RUNTIME_EVIDENCE_TEMPLATES],
    }


def runtime_item(template, host_memory_template, container_memory_template):
    source_reference = "http://observability-gateway:3100/loki/api/v1/query_range" if template == "loki.container.restarts.v1" else "http://observability-gateway:9090/api/v1/query_range"
    measurements = []
    if template == host_memory_template:
        measurements.append({
            "entity_type": "HOST", "entity_id": "demo-host", "host_id": "demo-host",
            "measurement": {"samples": [{"timestamp": "2026-11-27T05:00:00Z", "value": 1024}], "source_reference": source_reference},
        })
    if template == container_memory_template:
        measurements.append({
            "entity_type": "CONTAINER", "entity_id": "opaque-cgroup-id", "host_id": "demo-host",
            "mapping_status": "raw_cgroup_only",
            "measurement": {"samples": [{"timestamp": "2026-11-27T05:00:00Z", "value": 4096}], "source_reference": source_reference},
        })
    return {
        "id": "runtime-" + template,
        "source_type": "RUNTIME",
        "entity_type": "HOST",
        "entity_id": "demo-host",
        "completeness": "PARTIAL",
        "raw_reference": source_reference,
        "query_parameters": {
            "runtime": "docker-compose",
            "service": "inventory",
            "environment": "demo",
            "host_id": "demo-host",
            "mapping_version": 1,
            "template_id": template,
            "template_version": 1,
        },
        "value_summary": {
            "measurements": measurements, "events": [], "gaps": ["healthy_peer_evidence_unavailable"],
            "partial": True, "source_reference_available": True,
        },
    }


class DemoRuntimeEvidenceTests(unittest.TestCase):
    def load_smoke(self):
        spec = importlib.util.spec_from_file_location("demo_runtime_smoke_assert", ROOT / "scripts/demo-assert.py")
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        return smoke

    def test_runtime_mapping_is_fixed_scoped_and_read_only(self):
        mapping = runtime_mapping_payload("project-id", "inventory-id")
        self.assertEqual(mapping["source_type"], "RUNTIME")
        self.assertEqual(mapping["runtime_type"], "docker-compose")
        self.assertEqual(mapping["environment"], "demo")
        self.assertEqual(mapping["public_settings"]["runtime_labels"], {
            "project": "relythra-demo", "service": "inventory", "env": "demo",
            "host_id": "demo-host", "container_id": "unmapped",
        })
        self.assertEqual(mapping["template_ids"], [
            "runtime.containers.v1", "runtime.host.v1", "runtime.events.v1",
        ])
        self.assertEqual(mapping["public_settings"]["container_mappings"], [])
        self.assertNotIn("secret_ref", mapping)

    def test_runtime_mapping_is_created_through_authenticated_management_api(self):
        smoke = self.load_smoke()
        mapping = runtime_mapping_payload("project-id", "inventory-id")
        response = FakeResponse(b'{"data":{"secret_status":"not_configured"}}')
        response.status = 201
        with tempfile.TemporaryDirectory() as directory:
            secret_path = Path(directory) / "management_token"
            secret_path.write_text("demo-management-canary")
            with patch.dict(os.environ, {"RELYTHRA_MANAGEMENT_TOKEN_FILE": str(secret_path)}), \
                 patch.object(smoke.urllib.request, "urlopen", return_value=response) as call, \
                 patch("builtins.print"):
                smoke.configure_mapping(mapping, "Runtime")
            request = call.call_args.args[0]
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.get_header("Authorization"), "Bearer demo-management-canary")
            self.assertEqual(json.loads(request.data), mapping)
            self.assertNotIn("demo-management-canary", request.data.decode())

    def test_runtime_mode_reads_all_eight_records_and_verifies_each_evidence_link(self):
        smoke = self.load_smoke()
        timeline = runtime_timeline()
        responses = {"/api/v1/investigations/demo-investigation/timeline?source_type=RUNTIME&limit=100":
                     (200, json.dumps({"data": timeline}).encode())}
        for item in timeline["items"]:
            evidence = dict(item)
            evidence["investigation_id"] = "demo-investigation"
            responses[f"/api/v1/evidence/{item['id']}"] = (200, json.dumps({"data": evidence}).encode())

        with patch.object(smoke, "http", side_effect=lambda port, path: responses[path]) as request, \
             patch("builtins.print"):
            smoke.runtime_evidence("demo-investigation", "demo-host")

        self.assertEqual(request.call_count, 9)
        self.assertEqual(request.call_args_list[0].args, (28080, "/api/v1/investigations/demo-investigation/timeline?source_type=RUNTIME&limit=100"))

    def test_runtime_timeline_requires_all_eight_host_scoped_records(self):
        timeline = runtime_timeline()
        items = assert_runtime_evidence_timeline(timeline, "demo-investigation", "demo-host")
        self.assertEqual(set(items), set(RUNTIME_EVIDENCE_TEMPLATES))

    def test_runtime_timeline_rejects_all_empty_host_and_cgroup_memory_results(self):
        timeline = runtime_timeline()
        required_templates = ("prometheus.runtime.host.memory_available.v1", "prometheus.runtime.container.memory.v1")
        for item in timeline["items"]:
            if item["query_parameters"]["template_id"] in required_templates:
                item["value_summary"]["measurements"] = []
                item["raw_reference"] = ""
                item["value_summary"]["source_reference_available"] = False
        with self.assertRaisesRegex(AssertionError, "sample"):
            assert_runtime_evidence_timeline(timeline, "demo-investigation", "demo-host")

    def test_runtime_timeline_rejects_invalid_required_memory_samples(self):
        invalid_values = (True, -1, float("nan"), float("inf"), "1024")
        for value in invalid_values:
            with self.subTest(value=value):
                timeline = runtime_timeline()
                item = next(item for item in timeline["items"] if item["query_parameters"]["template_id"] == "prometheus.runtime.container.memory.v1")
                item["value_summary"]["measurements"][0]["measurement"]["samples"][0]["value"] = value
                with self.assertRaises(AssertionError):
                    assert_runtime_evidence_timeline(timeline, "demo-investigation", "demo-host")

    def test_runtime_timeline_rejects_wrong_scope_missing_templates_and_unbounded_claims(self):
        mutations = [
            lambda timeline: timeline.update(investigation_id="another-investigation"),
            lambda timeline: timeline["items"].pop(),
            lambda timeline: timeline["items"][0].update(entity_type="SERVICE"),
            lambda timeline: timeline["items"][0].update(entity_id="orders-host"),
            lambda timeline: timeline["items"][0]["query_parameters"].update(host_id="orders-host"),
            lambda timeline: timeline["items"][0]["query_parameters"].update(template_version=2),
            lambda timeline: timeline["items"][0].update(completeness="COMPLETE"),
            lambda timeline: timeline["items"][0]["value_summary"]["gaps"].clear(),
            lambda timeline: timeline["items"][0].update(raw_reference="http://127.0.0.1:1234/private"),
        ]
        for mutate in mutations:
            timeline = runtime_timeline()
            mutate(timeline)
            with self.subTest(timeline=timeline), self.assertRaises(AssertionError):
                assert_runtime_evidence_timeline(timeline, "demo-investigation", "demo-host")


class DemoArtifactTests(unittest.TestCase):
    def test_grafana_webhook_secret_is_redacted_from_failure_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            key = "grafana-hmac-canary-value"
            (Path(directory) / "grafana_webhook_secret").write_text(key, encoding="utf-8")
            known_secrets = read_secrets(directory)
            self.assertIn(key, known_secrets)
            self.assertNotIn(key, redact("webhook=" + key, known_secrets))

    def test_redact_removes_known_and_structured_credentials(self):
        value = 'Authorization: Bearer abc123 password="hunter2"'

        result = redact(value, ["abc123"])

        self.assertNotIn("abc123", result)
        self.assertNotIn("hunter2", result)
        self.assertIn("[REDACTED]", result)

    def test_redact_removes_quoted_json_credentials_and_basic_auth(self):
        credential = base64.b64encode(b"admin:example").decode()
        value = json.dumps({"password": "hidden-pass", "token": "hidden-token", "Authorization": f"Basic {credential}"})

        result = redact(value, [])

        for secret in ("hidden-pass", "hidden-token", credential):
            self.assertNotIn(secret, result)

    def test_redacted_json_with_escaped_quotes_remains_valid(self):
        value = json.dumps({"password": 'a"b', "token": "sample-token", "data": {"result": []}})

        result = redact(value, [])
        parsed = json.loads(result)

        self.assertEqual(parsed["password"], "[REDACTED]")
        self.assertEqual(parsed["token"], "[REDACTED]")
        self.assertNotIn('a\\"b', result)

    def test_write_capture_truncates_and_restricts_file_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capture.txt"

            write_capture(output, b"x" * (MAX_CAPTURE_BYTES + 1), [])

            self.assertLessEqual(output.stat().st_size, MAX_CAPTURE_BYTES)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)

    def test_compose_capture_limits_output(self):
        with tempfile.TemporaryDirectory() as directory:
            docker = Path(directory) / "docker"
            docker.write_text("#!/bin/sh\nyes x | head -c 3000000\n", encoding="utf-8")
            docker.chmod(0o755)
            with patch.dict(os.environ, {"PATH": directory + os.pathsep + os.environ["PATH"]}):
                result = compose_command("demo-test", "logs")
            self.assertLessEqual(len(result.stdout) + len(result.stderr), MAX_CAPTURE_BYTES + 32)

    def test_truncated_http_does_not_leak_secret_prefix(self):
        secret = "s" * 64
        body = b"x" * (MAX_CAPTURE_BYTES - 50) + secret.encode() + b"x" * 100
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "response.json"
            with patch("demo_artifacts.urllib.request.OpenerDirector.open", return_value=FakeResponse(body)):
                collect_http("http://127.0.0.1/test", output, "", [secret])
            self.assertFalse("s" * 30 in output.read_text(), "truncated HTTP response leaks a secret prefix")

    def test_truncated_compose_does_not_leak_secret_prefix(self):
        secret = "s" * 64
        with tempfile.TemporaryDirectory() as directory:
            docker = Path(directory) / "docker"
            docker.write_text(
                "#!/usr/bin/env python3\nimport sys\nsys.stdout.write('x' * (1048576 - 50) + 's' * 64 + 'x' * 100)\n",
                encoding="utf-8",
            )
            docker.chmod(0o755)
            with patch.dict(os.environ, {"PATH": directory + os.pathsep + os.environ["PATH"]}):
                capture_compose("demo-test", directory, [secret])
            self.assertFalse("s" * 30 in (Path(directory) / "compose-logs.txt").read_text(), "truncated Compose output leaks a secret prefix")

    def test_truncated_http_removes_partial_secret_after_prior_replacement(self):
        secret = "s" * 64
        limit = MAX_CAPTURE_BYTES + len(secret) + 1
        body = secret.encode() * 3 + b"x" * (limit - 3 * len(secret) - 32) + b"s" * 32 + b"x" * 100
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "response.json"
            with patch("demo_artifacts.urllib.request.OpenerDirector.open", return_value=FakeResponse(body)):
                collect_http("http://127.0.0.1/test", output, "", [secret])
            self.assertFalse("s" * 30 in output.read_text(), "partial secret survived truncation")

    def test_truncated_compose_removes_partial_secret_after_prior_replacement(self):
        secret = "s" * 64
        with tempfile.TemporaryDirectory() as directory:
            docker = Path(directory) / "docker"
            docker.write_text(
                "#!/usr/bin/env python3\nimport sys\n"
                "sys.stdout.write(('s' * 64 + 'z') * 3 + 'x' * (1048576 + 65 - 195 - 32) + 's' * 32 + 'x' * 100)\n",
                encoding="utf-8",
            )
            docker.chmod(0o755)
            with patch.dict(os.environ, {"PATH": directory + os.pathsep + os.environ["PATH"]}):
                capture_compose("demo-test", directory, [secret])
            self.assertFalse("s" * 30 in (Path(directory) / "compose-logs.txt").read_text(), "partial secret survived truncation")

    def test_partial_secret_removal_uses_longest_match_across_all_secrets(self):
        secrets = ["b" * 64, "a" * 31 + "b" + "c" * 32]
        for ordered in (secrets, list(reversed(secrets))):
            self.assertEqual(remove_partial_secret("prefix-" + "a" * 31 + "b", ordered), "prefix-[REDACTED]")

    def test_truncated_compose_stderr_removes_partial_secret(self):
        secret = "s" * 64
        result = subprocess.CompletedProcess([], -9, b"", b"details " + b"s" * 32 + b"\n[truncated]\n")

        _, stderr = safe_compose_output(result, [secret])

        self.assertNotIn(b"s" * 30, stderr)

    def test_collect_http_saves_bounded_response(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "prometheus.json"

            collect_http("http://127.0.0.1:1/unavailable", output, "", [])

            self.assertTrue(output.with_suffix(".error.txt").exists())
            self.assertFalse(output.exists())

    def test_collect_writes_private_bundle_and_redacts_captured_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secrets = root / "secrets"
            secrets.mkdir(mode=0o700)
            (secrets / "observability_token").write_text("sample-token", encoding="utf-8")
            output = root / "artifacts" / "run"

            def compose_result(_project, *args, **_kwargs):
                if args[:4] == ("ps", "--all", "--format", "json"):
                    body = (
                        b'{"Service":"observability-gateway","State":"running"}\n'
                        b'{"Service":"grafana","State":"running"}'
                    )
                else:
                    body = b"Authorization: Bearer sample-token"
                return subprocess.CompletedProcess([], 0, body, b"")

            with patch.dict(os.environ, {"DEMO_OBSERVABILITY_TOKEN_FILE": str(secrets / "observability_token")}):
                with patch("demo_artifacts.compose_command", side_effect=compose_result):
                    with patch("demo_artifacts.urllib.request.OpenerDirector.open", return_value=FakeResponse(b'{"token":"sample-token"}')):
                        collect("demo-test", output, secrets)

            expected_files = {
                "README.txt",
                "compose-status.txt",
                "compose-logs.txt",
                "prometheus-up.json",
                "prometheus-orders-latency.json",
                "prometheus-service-info.json",
                "loki-business-logs.json",
                "loki-inventory-logs.json",
                "grafana-health.json",
            }
            self.assertEqual({path.name for path in output.iterdir()}, expected_files | {
                "prometheus-up.request.txt",
                "prometheus-orders-latency.request.txt",
                "prometheus-service-info.request.txt",
                "loki-business-logs.request.txt",
                "loki-inventory-logs.request.txt",
                "grafana-health.request.txt",
                "prometheus-up.status.txt",
                "prometheus-orders-latency.status.txt",
                "prometheus-service-info.status.txt",
                "loki-business-logs.status.txt",
                "loki-inventory-logs.status.txt",
                "grafana-health.status.txt",
            })
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o700)
            for path in output.iterdir():
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
                self.assertNotIn("sample-token", path.read_text(encoding="utf-8"))

    def test_collect_does_not_query_ports_without_owned_observability_gateway(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secrets = root / "secrets"
            secrets.mkdir(mode=0o700)
            output = root / "artifacts" / "run"
            ps = subprocess.CompletedProcess([], 0, b"[]", b"")
            other = subprocess.CompletedProcess([], 0, b"", b"")

            with patch("demo_artifacts.compose_command", side_effect=[ps, other]):
                with patch("demo_artifacts.urllib.request.OpenerDirector.open") as urlopen:
                    collect("demo-test", output, secrets)

            urlopen.assert_not_called()
            self.assertIn("skipped", (output / "prometheus-up.error.txt").read_text(encoding="utf-8"))
            self.assertIn("skipped", (output / "loki-business-logs.error.txt").read_text(encoding="utf-8"))

    def test_smoke_failure_saves_redacted_bundle_and_preserves_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "cleanup-ran"
            fake_docker = fake_bin / "docker"
            fake_docker.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *' config --format json'*) exit 17 ;;\n"
                "  *' ps --all --format json'*) printf '[]\\n' ;;\n"
                "  *' logs --no-color'*) token=\"$(cat \"$DEMO_OBSERVABILITY_TOKEN_FILE\")\"; "
                f"printf '%s' \"$token\" > '{marker}.token'; printf 'Authorization: Bearer %s\\n' \"$token\" ;;\n"
                f"  *' down --volumes --remove-orphans'*) touch '{marker}' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o700)
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "TMPDIR": str(root),
                    "RELYTHRA_DEMO_ARTIFACT_DIR": str(root / "artifacts"),
                }
            )

            result = subprocess.run(
                ["bash", str(ROOT / "scripts/demo-smoke.sh")],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            self.assertEqual(result.returncode, 17, result.stderr)
            self.assertTrue(marker.exists(), "Compose cleanup must run after a smoke failure")
            bundle_dirs = list((root / "artifacts").iterdir())
            self.assertEqual(len(bundle_dirs), 1)
            readme = (bundle_dirs[0] / "README.txt").read_text(encoding="utf-8")
            self.assertIn("Failed stage: render and verify Compose configuration", readme)
            self.assertIn("Exit code: 17", readme)
            logs = (bundle_dirs[0] / "compose-logs.txt").read_text(encoding="utf-8")
            token = Path(f"{marker}.token").read_text(encoding="utf-8")
            self.assertNotIn(token, logs)
            self.assertNotIn("compose.json", {path.name for path in bundle_dirs[0].iterdir()})
            self.assertFalse(list(root.glob("relythra-demo-smoke.*")), "temporary secrets must be removed")


if __name__ == "__main__":
    unittest.main()
