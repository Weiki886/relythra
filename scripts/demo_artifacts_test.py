import base64
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from demo_artifacts import MAX_CAPTURE_BYTES, capture_compose, collect, collect_http, compose_command, read_secrets, redact, remove_partial_secret, safe_compose_output, write_capture

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
