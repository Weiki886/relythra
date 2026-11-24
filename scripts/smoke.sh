#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/deploy/compose/compose.yaml"

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/relythra-smoke.XXXXXX")"
chmod 0700 "${temp_dir}"
trap 'rm -rf "${temp_dir}"' EXIT

if [ -n "${RELYTHRA_POSTGRES_PASSWORD:-}" ]; then
  RELYTHRA_POSTGRES_PASSWORD_FILE="${temp_dir}/postgres_password"
  (
    umask 077
    printf '%s' "${RELYTHRA_POSTGRES_PASSWORD}" >"${RELYTHRA_POSTGRES_PASSWORD_FILE}"
  )
  unset RELYTHRA_POSTGRES_PASSWORD
fi

if [ -n "${RELYTHRA_MANAGEMENT_TOKEN:-}" ]; then
  RELYTHRA_MANAGEMENT_TOKEN_FILE="${temp_dir}/management_token"
  (
    umask 077
    printf '%s' "${RELYTHRA_MANAGEMENT_TOKEN}" >"${RELYTHRA_MANAGEMENT_TOKEN_FILE}"
  )
  unset RELYTHRA_MANAGEMENT_TOKEN
elif [ -z "${RELYTHRA_MANAGEMENT_TOKEN_FILE:-}" ]; then
  RELYTHRA_MANAGEMENT_TOKEN_FILE="${temp_dir}/management_token"
  (
    umask 077
    {
      printf 'smoke-'
      od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
    } >"${RELYTHRA_MANAGEMENT_TOKEN_FILE}"
  )
fi

: "${RELYTHRA_POSTGRES_PASSWORD_FILE:?Set RELYTHRA_POSTGRES_PASSWORD_FILE or RELYTHRA_POSTGRES_PASSWORD before running smoke tests}"
: "${RELYTHRA_MANAGEMENT_TOKEN_FILE:?Set RELYTHRA_MANAGEMENT_TOKEN_FILE or allow smoke to generate one}"
test -r "${RELYTHRA_POSTGRES_PASSWORD_FILE}" || {
  printf 'PostgreSQL password file is not readable: %s\n' "${RELYTHRA_POSTGRES_PASSWORD_FILE}" >&2
  exit 1
}
test -r "${RELYTHRA_MANAGEMENT_TOKEN_FILE}" || {
  printf 'Management token file is not readable: %s\n' "${RELYTHRA_MANAGEMENT_TOKEN_FILE}" >&2
  exit 1
}
management_token="$(cat "${RELYTHRA_MANAGEMENT_TOKEN_FILE}")"
test -n "${management_token}" || {
  printf 'Management token file is empty: %s\n' "${RELYTHRA_MANAGEMENT_TOKEN_FILE}" >&2
  exit 1
}
export RELYTHRA_POSTGRES_PASSWORD_FILE
export RELYTHRA_MANAGEMENT_TOKEN_FILE
export RELYTHRA_API_PORT="${RELYTHRA_API_PORT:-18080}"
export RELYTHRA_WORKER_PORT="${RELYTHRA_WORKER_PORT:-18081}"
export RELYTHRA_WEB_PORT="${RELYTHRA_WEB_PORT:-13000}"
export RELYTHRA_POSTGRES_PORT="${RELYTHRA_POSTGRES_PORT:-15432}"

COMPOSE=(docker compose --project-name relythra-smoke --file "${COMPOSE_FILE}")

cleanup() {
  local exit_status=$?
  if [ "${exit_status}" -ne 0 ]; then
    printf 'Compose smoke failed with exit %s; collecting service logs.\n' "${exit_status}" >&2
    "${COMPOSE[@]}" ps --all || true
    "${COMPOSE[@]}" logs --no-color --tail 200 postgres migrate api worker web || true
  fi
  if ! "${COMPOSE[@]}" down --volumes --remove-orphans; then
    printf 'Failed to remove Compose smoke resources.\n' >&2
    exit_status=1
  fi
  rm -rf "${temp_dir}" || true
  exit "${exit_status}"
}
trap cleanup EXIT

"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" up --build --wait --wait-timeout 180

# A second run must be a successful no-op after the empty-database migration.
"${COMPOSE[@]}" run --rm --no-deps migrate up

curl --fail --silent --show-error "http://localhost:${RELYTHRA_API_PORT}/health/live" \
  | grep --fixed-strings '"status":"ok"'
curl --fail --silent --show-error "http://localhost:${RELYTHRA_API_PORT}/health/ready" \
  | grep --fixed-strings '"status":"ready"'
test "$("${COMPOSE[@]}" exec -T api awk '$1 == "Uid:" { print $2 }' /proc/1/status)" = "10001"
"${COMPOSE[@]}" exec -T --user 10001 api test -r /run/relythra-secrets/postgres_password
"${COMPOSE[@]}" exec -T --user 10001 api test -r /run/relythra-secrets/management_token
"${COMPOSE[@]}" exec -T postgres \
  psql --set=ON_ERROR_STOP=1 --username relythra --dbname relythra \
  < "${ROOT_DIR}/scripts/smoke_domain.sql"
curl --fail --silent --show-error \
  "http://localhost:${RELYTHRA_API_PORT}/api/v1/reports/10000000-0000-4000-8000-000000000011" \
  | grep --fixed-strings '"summary":"Deployment introduced a slow query"'
curl --fail --silent --show-error \
  "http://localhost:${RELYTHRA_API_PORT}/api/v1/evidence/10000000-0000-4000-8000-000000000009" \
  | grep --fixed-strings '"source_type":"PROMETHEUS"'
curl --fail --silent --show-error \
  "http://localhost:${RELYTHRA_API_PORT}/api/v1/deployments/10000000-0000-4000-8000-000000000004" \
  | grep --fixed-strings '"source_time_text":"2026-11-04T13:00:00+08:00"'

api_url="http://localhost:${RELYTHRA_API_PORT}/api/v1/data-source-mappings"

unauthorized_response="${temp_dir}/unauthorized.json"
unauthorized_status="$(curl --silent --show-error \
  --header 'X-Request-ID: smoke-unauthorized-1' \
  --output "${unauthorized_response}" \
  --write-out '%{http_code}' \
  "${api_url}")"
test "${unauthorized_status}" = "401"
grep --fixed-strings '"code":"unauthorized"' "${unauthorized_response}"

mapping_body="${temp_dir}/mapping.json"
cat >"${mapping_body}" <<'JSON'
{
  "project_id": "10000000-0000-4000-8000-000000000001",
  "service_id": "10000000-0000-4000-8000-000000000002",
  "environment": "prod",
  "source_type": "PROMETHEUS",
  "public_settings": {
    "endpoint": "http://prometheus:9090"
  },
  "template_ids": [
    "prometheus.service.latency.v1"
  ],
  "secret_ref": "env:SMOKE_DATASOURCE_TOKEN"
}
JSON
mapping_response="${temp_dir}/mapping-response.json"
mapping_status="$(curl --silent --show-error \
  --header "Authorization: Bearer ${management_token}" \
  --header 'Content-Type: application/json' \
  --header 'X-Request-ID: smoke-mapping-create' \
  --data-binary "@${mapping_body}" \
  --output "${mapping_response}" \
  --write-out '%{http_code}' \
  "${api_url}")"
test "${mapping_status}" = "201"
if grep --fixed-strings 'env:SMOKE_DATASOURCE_TOKEN' "${mapping_response}"; then
  printf 'Mapping response exposed SecretRef.\n' >&2
  exit 1
fi
grep --fixed-strings '"secret_status":"configured"' "${mapping_response}"
mapping_id="$(sed -n 's/.*"id":"\([^"]*\)","project_id".*/\1/p' "${mapping_response}")"
test -n "${mapping_id}"

validation_response="${temp_dir}/validation-response.json"
curl --fail --silent --show-error \
  --request POST \
  --header "Authorization: Bearer ${management_token}" \
  --header 'X-Request-ID: smoke-mapping-validate' \
  --output "${validation_response}" \
  "${api_url}/${mapping_id}/validate"
grep --fixed-strings '"valid":true' "${validation_response}"

query_body="${temp_dir}/query.json"
cat >"${query_body}" <<'JSON'
{
  "template_id": "prometheus.service.latency.v1",
  "parameters": {
    "service": "checkout-api",
    "environment": "prod",
    "start": "2026-11-04T05:00:00Z",
    "end": "2026-11-04T05:10:00Z"
  }
}
JSON
query_response="${temp_dir}/query-response.json"
curl --fail --silent --show-error \
  --header "Authorization: Bearer ${management_token}" \
  --header 'Content-Type: application/json' \
  --header 'X-Request-ID: smoke-mapping-query' \
  --data-binary "@${query_body}" \
  --output "${query_response}" \
  "${api_url}/${mapping_id}/queries"
grep --fixed-strings '"template_id":"prometheus.service.latency.v1"' "${query_response}"
grep --fixed-strings '"environment":"prod"' "${query_response}"
grep --fixed-strings '"step":30000000000' "${query_response}"
grep --fixed-strings '"max_points":1000' "${query_response}"

instant_query_body="${temp_dir}/instant-query.json"
cat >"${instant_query_body}" <<'JSON'
{
  "template_id": "prometheus.service.latency.v1",
  "parameters": {
    "service": "checkout-api",
    "environment": "prod",
    "query_type": "instant",
    "at": "2026-11-04T05:05:00Z"
  }
}
JSON
instant_query_response="${temp_dir}/instant-query-response.json"
curl --fail --silent --show-error \
  --header "Authorization: Bearer ${management_token}" \
  --header 'Content-Type: application/json' \
  --header 'X-Request-ID: smoke-mapping-instant-query' \
  --data-binary "@${instant_query_body}" \
  --output "${instant_query_response}" \
  "${api_url}/${mapping_id}/queries"
grep --fixed-strings '"query_type":"instant"' "${instant_query_response}"
grep --fixed-strings '"max_points":1' "${instant_query_response}"

stale_body="${temp_dir}/stale.json"
sed '1s/^{/{"expected_version":999,/' "${mapping_body}" >"${stale_body}"
stale_response="${temp_dir}/stale-response.json"
stale_status="$(curl --silent --show-error \
  --request PUT \
  --header "Authorization: Bearer ${management_token}" \
  --header 'Content-Type: application/json' \
  --header 'X-Request-ID: smoke-mapping-stale' \
  --data-binary "@${stale_body}" \
  --output "${stale_response}" \
  --write-out '%{http_code}' \
  "${api_url}/${mapping_id}")"
test "${stale_status}" = "409"
grep --fixed-strings '"code":"stale_version"' "${stale_response}"

curl --fail --silent --show-error \
  --header "Authorization: Bearer ${management_token}" \
  "${api_url}?project_id=10000000-0000-4000-8000-000000000001&environment=prod" \
  | grep --fixed-strings "\"id\":\"${mapping_id}\""

runtime_body="${temp_dir}/runtime.json"
cat >"${runtime_body}" <<'JSON'
{
  "project_id": "10000000-0000-4000-8000-000000000001",
  "service_id": "10000000-0000-4000-8000-000000000002",
  "environment": "prod",
  "source_type": "RUNTIME",
  "runtime_type": "docker-compose",
  "public_settings": {
    "endpoint": "http://cadvisor:8080"
  },
  "template_ids": [
    "runtime.containers.v1"
  ]
}
JSON
runtime_response="${temp_dir}/runtime-response.json"
runtime_status="$(curl --silent --show-error \
  --header "Authorization: Bearer ${management_token}" \
  --header 'Content-Type: application/json' \
  --header 'X-Request-ID: smoke-runtime-draft' \
  --data-binary "@${runtime_body}" \
  --output "${runtime_response}" \
  --write-out '%{http_code}' \
  "${api_url}")"
test "${runtime_status}" = "201"
runtime_mapping_id="$(sed -n 's/.*"id":"\([^"]*\)","project_id".*/\1/p' "${runtime_response}")"
test -n "${runtime_mapping_id}"
runtime_validation_response="${temp_dir}/runtime-validation-response.json"
curl --fail --silent --show-error \
  --request POST \
  --header "Authorization: Bearer ${management_token}" \
  --header 'X-Request-ID: smoke-runtime-validate' \
  --output "${runtime_validation_response}" \
  "${api_url}/${runtime_mapping_id}/validate"
grep --fixed-strings '"valid":false' "${runtime_validation_response}"
grep --fixed-strings '"field":"runtime_labels.project"' "${runtime_validation_response}"

"${COMPOSE[@]}" exec -T postgres \
  psql --set=ON_ERROR_STOP=1 --username relythra --dbname relythra \
  < "${ROOT_DIR}/scripts/smoke_management.sql"

curl --fail --silent --show-error "http://localhost:${RELYTHRA_WORKER_PORT}/metrics" \
  | grep --fixed-strings 'relythra_worker_heartbeat_timestamp_seconds'
curl --fail --silent --show-error "http://localhost:${RELYTHRA_WEB_PORT}/" \
  | grep --fixed-strings '<title>Relythra</title>'

# Browser reads must reach the API instead of the SPA fallback.
web_diagnosis_status="$(curl --silent --show-error --output "${temp_dir}/web-diagnosis.json" --write-out '%{http_code}' \
  "http://localhost:${RELYTHRA_WEB_PORT}/api/v1/investigations/00000000-0000-4000-8000-000000000000/diagnosis")"
test "${web_diagnosis_status}" = "404"
grep --fixed-strings '"code":"not_found"' "${temp_dir}/web-diagnosis.json"

web_context_status="$(curl --silent --show-error --output "${temp_dir}/web-context-missing.json" --write-out '%{http_code}' \
  "http://localhost:${RELYTHRA_WEB_PORT}/api/v1/investigations/00000000-0000-4000-8000-000000000000")"
test "${web_context_status}" = "404"
grep --fixed-strings '"code":"not_found"' "${temp_dir}/web-context-missing.json"
curl --fail --silent --show-error \
  --output "${temp_dir}/web-context.json" \
  "http://localhost:${RELYTHRA_WEB_PORT}/api/v1/investigations/10000000-0000-4000-8000-000000000007"
grep --fixed-strings '"investigation_id":"10000000-0000-4000-8000-000000000007"' "${temp_dir}/web-context.json"
grep --fixed-strings '"mapping_status":"MATCHED"' "${temp_dir}/web-context.json"
grep --fixed-strings '"alert":null' "${temp_dir}/web-context.json"
if grep --extended-regexp '"(secret_ref|redacted_payload|labels|annotations)"' "${temp_dir}/web-context.json"; then
  printf 'Investigation context exposed fields outside its projection.\n' >&2
  exit 1
fi

# Losing PostgreSQL must fail readiness without taking down the API process.
"${COMPOSE[@]}" stop postgres
readiness_status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  "http://localhost:${RELYTHRA_API_PORT}/health/ready")"
test "${readiness_status}" = "503"
curl --silent --show-error "http://localhost:${RELYTHRA_API_PORT}/health/ready" \
  | grep --fixed-strings '"error":"dependency unavailable"'
curl --fail --silent --show-error "http://localhost:${RELYTHRA_API_PORT}/health/live" \
  | grep --fixed-strings '"status":"ok"'
"${COMPOSE[@]}" logs --no-color api | grep --fixed-strings 'readiness check failed'

printf 'Smoke checks passed: migrations, secure mapping management, traceable reads, healthy services, and database-loss behavior.\n'
