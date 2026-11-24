#!/usr/bin/env python3
"""Capture bounded, redacted diagnostics after a disposable demo smoke failure."""
import argparse
import datetime
import http.client
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


MAX_CAPTURE_BYTES = 1024 * 1024
TRUNCATION_MARKER = b"\n[truncated]\n"
AUTHORIZATION = re.compile(r"(?i)(authorization[\"']?\s*[:=]\s*[\"']?)(?:bearer|basic)\s+[^\s,;\"']+")
SENSITIVE_VALUE = re.compile(
    r"(?i)((?:password|token|secret|authorization)[\"']?\s*[:=]\s*)"
    r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;]+)"
)



class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def redact(value, secrets):
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    for secret in secrets:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    value = AUTHORIZATION.sub(r"\1[REDACTED]", value)
    def replace_sensitive(match):
        original = match.group(2)
        quote = original[0] if original.startswith(('"', "'")) else ""
        return match.group(1) + quote + "[REDACTED]" + quote

    return SENSITIVE_VALUE.sub(replace_sensitive, value)


def remove_partial_secret(content, secrets):
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    longest = 0
    for secret in secrets:
        for length in range(min(len(secret) - 1, len(content)), longest, -1):
            if content.endswith(secret[:length]):
                longest = length
                break
    if longest:
        return content[:-longest] + "[REDACTED]"
    return content


def write_capture(path, content, secrets):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    payload = redact(content, secrets).encode("utf-8")
    if len(payload) > MAX_CAPTURE_BYTES:
        payload = payload[: MAX_CAPTURE_BYTES - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
    os.chmod(path, 0o600)


def collect_http(url, output, token, secrets):
    capture_limit = MAX_CAPTURE_BYTES + max((len(secret.encode("utf-8")) for secret in secrets), default=0) + 1
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = urllib.request.Request(url, headers=headers)
    write_capture(Path(output).with_suffix(".request.txt"), url, secrets)
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(request, timeout=5) as response:
            body = response.read(capture_limit)
            if len(body) == capture_limit:
                body = remove_partial_secret(body, secrets)
            write_capture(output, body, secrets)
            write_capture(Path(output).with_suffix(".status.txt"), str(response.status), secrets)
    except urllib.error.HTTPError as error:
        body = error.read(capture_limit)
        if len(body) == capture_limit:
            body = remove_partial_secret(body, secrets)
        write_capture(output, body, secrets)
        write_capture(Path(output).with_suffix(".status.txt"), str(error.code), secrets)
    except (OSError, TimeoutError, urllib.error.URLError, http.client.HTTPException) as error:
        write_capture(Path(output).with_suffix(".error.txt"), str(error), secrets)


def read_secrets(directory):
    values = []
    if directory and Path(directory).is_dir():
        for name in ("postgres_password", "management_token", "demo_owner_password", "demo_reader_password", "observability_token", "grafana_admin_password", "grafana_webhook_secret"):
            path = Path(directory) / name
            if path.is_file():
                try:
                    value = path.read_text(encoding="utf-8").strip()
                except (OSError, UnicodeError):
                    continue
                if value:
                    values.append(value)
    token_file = os.environ.get("DEMO_OBSERVABILITY_TOKEN_FILE")
    if token_file:
        try:
            token = Path(token_file).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            token = ""
        if token and token not in values:
            values.append(token)
    return values


def compose_command(project, *args, capture_limit=MAX_CAPTURE_BYTES):
    root = Path(__file__).resolve().parent.parent
    command = [
        "docker", "compose", "--env-file", "/dev/null", "--project-name", project,
        "--file", str(root / "deploy/compose/compose.yaml"),
        "--file", str(root / "deploy/compose/demo.yaml"), *args,
    ]
    process = subprocess.Popen(
        command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    )
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    deadline = time.monotonic() + 15
    truncated = False
    try:
        with selectors.DefaultSelector() as selector:
            for stream in streams:
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, 15)
                for key, _ in selector.select(remaining):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    available = capture_limit - sum(len(value) for value in streams.values())
                    streams[key.fileobj].extend(data[:available])
                    if len(data) > available:
                        truncated = True
                        break
                if truncated:
                    break
        if truncated:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        for stream in streams:
            stream.close()
    stdout, stderr = (bytes(value) for value in streams.values())
    if truncated:
        stderr += TRUNCATION_MARKER
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)



def running_compose_services(raw):
    try:
        rows = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        rows = []
        for line in raw.splitlines():
            try:
                rows.append(json.loads(line))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return set()
    return {
        row.get("Service")
        for row in rows
        if isinstance(row, dict) and row.get("State") == "running" and row.get("Service")
    }


def safe_compose_output(result, secrets):
    if not result.stderr.endswith(TRUNCATION_MARKER):
        return result.stdout, result.stderr
    stdout = remove_partial_secret(result.stdout, secrets).encode("utf-8")
    stderr = remove_partial_secret(result.stderr[:-len(TRUNCATION_MARKER)], secrets).encode("utf-8")
    return stdout, stderr + TRUNCATION_MARKER


def capture_compose(project, output_dir, secrets):
    capture_limit = MAX_CAPTURE_BYTES + max((len(secret.encode("utf-8")) for secret in secrets), default=0) + 1
    try:
        status = compose_command(project, "ps", "--all", "--format", "json", capture_limit=capture_limit)
        stdout, stderr = safe_compose_output(status, secrets)
        status_content = b"exit_code=" + str(status.returncode).encode() + b"\n" + stdout + b"\n" + stderr
        services = running_compose_services(status.stdout)
    except (OSError, subprocess.TimeoutExpired) as error:
        status_content = f"capture_error={error}".encode()
        services = set()
    write_capture(Path(output_dir) / "compose-status.txt", status_content, secrets)

    for name, args in [
        (
            "compose-logs.txt",
            ("logs", "--no-color", "--tail", "100", "postgres", "migrate", "api", "worker", "web", "inventory", "orders", "demo-postgres", "prometheus-store", "loki-store", "alloy", "grafana", "cadvisor", "node-exporter", "observability-gateway"),
        ),
    ]:
        try:
            result = compose_command(project, *args, capture_limit=capture_limit)
            stdout, stderr = safe_compose_output(result, secrets)
            content = b"exit_code=" + str(result.returncode).encode() + b"\n" + stdout + b"\n" + stderr
        except (OSError, subprocess.TimeoutExpired) as error:
            content = f"capture_error={error}".encode()
        write_capture(Path(output_dir) / name, content, secrets)
    return services


def capture_queries(output_dir, token, secrets, running_services):
    if "observability-gateway" not in running_services:
        reason = "skipped: isolated Compose observability-gateway is not running"
        for name in [
            "prometheus-up.json",
            "prometheus-orders-latency.json",
            "prometheus-service-info.json",
            "loki-business-logs.json",
            "loki-inventory-logs.json",
        ]:
            write_capture(Path(output_dir) / name.replace(".json", ".error.txt"), reason, secrets)
    else:
        prometheus_port = os.environ.get("DEMO_PROMETHEUS_PORT", "29090")
        loki_port = os.environ.get("DEMO_LOKI_PORT", "23100")
        prometheus_queries = {
            "prometheus-up.json": "up",
            "prometheus-orders-latency.json": 'demo_http_request_duration_seconds_bucket{service="orders",route="/orders"}',
            "prometheus-service-info.json": "demo_service_info",
        }
        for name, query in prometheus_queries.items():
            url = f"http://127.0.0.1:{prometheus_port}/api/v1/query?{urllib.parse.urlencode({'query': query})}"
            collect_http(url, Path(output_dir) / name, token, secrets)

        end_ns = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1_000_000_000)
        start_ns = end_ns - 15 * 60 * 1_000_000_000
        loki_queries = {
            "loki-business-logs.json": '{project="relythra-demo",env="demo"} |= "request completed"',
            "loki-inventory-logs.json": '{project="relythra-demo",service="inventory",env="demo"} |= "request completed"',
        }
        for name, query in loki_queries.items():
            params = urllib.parse.urlencode({"query": query, "limit": 100, "direction": "backward", "start": start_ns, "end": end_ns})
            url = f"http://127.0.0.1:{loki_port}/loki/api/v1/query_range?{params}"
            collect_http(url, Path(output_dir) / name, token, secrets)

    grafana_port = os.environ.get("DEMO_GRAFANA_PORT", "23001")
    if "grafana" in running_services:
        collect_http(f"http://127.0.0.1:{grafana_port}/api/health", Path(output_dir) / "grafana-health.json", "", secrets)
    else:
        write_capture(
            Path(output_dir) / "grafana-health.error.txt",
            "skipped: isolated Compose grafana service is not running",
            secrets,
        )


def collect(project, output_dir, secret_dir, stage="unknown", exit_code=1):
    output = Path(output_dir)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    secrets = read_secrets(secret_dir)
    write_capture(
        output / "README.txt",
        f"Captured at {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n"
        f"Failed stage: {stage}\nExit code: {exit_code}\n"
        "Bounded diagnostics from a disposable demo smoke failure.\n"
        "Generated Compose config, environment, and secret files are intentionally excluded.\n",
        secrets,
    )
    running_services = capture_compose(project, output, secrets)
    token = ""
    token_file = os.environ.get("DEMO_OBSERVABILITY_TOKEN_FILE")
    if token_file:
        try:
            token = Path(token_file).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            pass
    capture_queries(output, token, secrets, running_services)
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("project")
    parser.add_argument("output_dir")
    parser.add_argument("secret_dir")
    parser.add_argument("stage")
    parser.add_argument("exit_code", type=int)
    args = parser.parse_args()
    try:
        output = collect(args.project, args.output_dir, args.secret_dir, args.stage, args.exit_code)
    except (OSError, ValueError) as error:
        print(f"Could not create demo diagnostics bundle: {error}", file=sys.stderr)
        return 1
    print(f"Demo failure diagnostics saved to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
