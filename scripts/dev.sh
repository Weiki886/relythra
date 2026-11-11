#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TMP_ROOT="${TMPDIR:-/tmp}"
RUN_DIR=""
LOG_DIR=""
DB_NAME="${RELYTHRA_DATABASE_NAME:-relythra}"
DB_HOST="${RELYTHRA_DATABASE_HOST:-${PGHOST:-127.0.0.1}}"
DB_PORT="${RELYTHRA_DATABASE_PORT:-${PGPORT:-5432}}"
DB_USER="${RELYTHRA_DATABASE_USER:-${PGUSER:-$(id -un)}}"
DB_SSL_MODE="${RELYTHRA_DATABASE_SSL_MODE:-${PGSSLMODE:-disable}}"
CUSTOM_DATABASE_CONFIGURATION=""

if [ -n "${RELYTHRA_DATABASE_URL:-}" ] ||
  [ -n "${RELYTHRA_DATABASE_URL_REF:-}" ] ||
  [ -n "${RELYTHRA_DATABASE_PASSWORD_REF:-}" ]; then
  CUSTOM_DATABASE_CONFIGURATION=1
else
  export RELYTHRA_DATABASE_URL="postgres://${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable"
fi

if [ -n "${RELYTHRA_DATABASE_PASSWORD_REF:-}" ]; then
  export RELYTHRA_DATABASE_HOST="${DB_HOST}"
  export RELYTHRA_DATABASE_PORT="${DB_PORT}"
  export RELYTHRA_DATABASE_NAME="${DB_NAME}"
  export RELYTHRA_DATABASE_USER="${DB_USER}"
  export RELYTHRA_DATABASE_SSL_MODE="${DB_SSL_MODE}"
fi

export RELYTHRA_API_ADDR="127.0.0.1:8080"
export RELYTHRA_WORKER_ADDR="127.0.0.1:8081"

API_URL="http://127.0.0.1:8080"
WORKER_URL="http://127.0.0.1:8081"
WEB_URL="http://127.0.0.1:5173"

api_pid=""
worker_pid=""
web_pid=""

usage() {
  cat <<'EOF'
Usage: ./scripts/dev.sh [--check|--help]

Start the local API, worker, and web development server without Docker.
PostgreSQL must already be running.

Environment:
  RELYTHRA_DATABASE_URL  PostgreSQL connection string.
                         Defaults to postgres://$USER@127.0.0.1:5432/relythra?sslmode=disable
  RELYTHRA_DATABASE_URL_REF
                         SecretRef containing the complete PostgreSQL DSN.
  RELYTHRA_DATABASE_PASSWORD_REF
                         SecretRef containing only the PostgreSQL password.
  RELYTHRA_DATABASE_HOST, RELYTHRA_DATABASE_PORT, RELYTHRA_DATABASE_NAME,
  RELYTHRA_DATABASE_USER, RELYTHRA_DATABASE_SSL_MODE
                         Connection fields used with a password SecretRef.
  PGHOST, PGPORT, PGUSER, PGSSLMODE
                         Defaults for the connection fields above.

SecretRefs accept env:NAME or file:/absolute/path.

Options:
  --check  Validate dependencies, prepare the local database, and print service URLs.
  --help   Show this help.
EOF
}

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command '$1' was not found"
}

resolve_secret_ref() {
  local reference="$1"
  local label="$2"
  local scheme
  local locator
  local value=""

  scheme="${reference%%:*}"
  if [ "${scheme}" = "${reference}" ]; then
    fail "${label} must use env:NAME or file:/absolute/path"
  fi
  locator="${reference#*:}"

  case "${scheme}" in
    env)
      if [[ ! "${locator}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        fail "${label} has an invalid environment variable name"
      fi
      set +u
      value="${!locator-}"
      set -u
      ;;
    file)
      if [[ "${locator}" != /* ]]; then
        fail "${label} secret file path must be absolute"
      fi
      if [ ! -f "${locator}" ] || [ ! -r "${locator}" ]; then
        fail "${label} secret file is not readable"
      fi
      if [ "$(wc -c <"${locator}" | tr -d '[:space:]')" -gt 65536 ]; then
        fail "${label} secret exceeds the 64 KiB limit"
      fi
      value="$(cat -- "${locator}"; printf x)"
      value="${value%x}"
      case "${value}" in
        *$'\r\n') value="${value%$'\r\n'}" ;;
        *$'\n') value="${value%$'\n'}" ;;
      esac
      ;;
    *)
      fail "${label} uses an unsupported SecretRef scheme"
      ;;
  esac

  if [[ ! "${value}" =~ [^[:space:]] ]]; then
    fail "${label} resolved to an empty value"
  fi
  printf '%s' "${value}"
}

database_psql() {
  local database_url
  local database_password

  if [ -n "${RELYTHRA_DATABASE_URL_REF:-}" ]; then
    database_url="$(resolve_secret_ref "${RELYTHRA_DATABASE_URL_REF}" RELYTHRA_DATABASE_URL_REF)"
    psql "${database_url}" --no-psqlrc --set ON_ERROR_STOP=1 \
      --tuples-only --no-align --command 'SELECT 1'
    return
  fi

  if [ -n "${RELYTHRA_DATABASE_PASSWORD_REF:-}" ]; then
    database_password="$(
      resolve_secret_ref "${RELYTHRA_DATABASE_PASSWORD_REF}" RELYTHRA_DATABASE_PASSWORD_REF
    )"
    PGPASSWORD="${database_password}" PGSSLMODE="${DB_SSL_MODE}" psql \
      --no-psqlrc --set ON_ERROR_STOP=1 --tuples-only --no-align \
      --dbname "${DB_NAME}" --username "${DB_USER}" --host "${DB_HOST}" --port "${DB_PORT}" \
      --command 'SELECT 1'
    return
  fi

  psql "${RELYTHRA_DATABASE_URL}" --no-psqlrc --set ON_ERROR_STOP=1 \
    --tuples-only --no-align --command 'SELECT 1'
}

preflight() {
  require_command go
  require_command node
  require_command npm
  require_command psql
  require_command curl

  if [ -z "${CUSTOM_DATABASE_CONFIGURATION}" ]; then
    require_command createdb
  fi
}

ensure_database() {
  if database_psql >/dev/null 2>&1; then
    return
  fi

  if [ -n "${CUSTOM_DATABASE_CONFIGURATION}" ]; then
    fail "cannot connect to PostgreSQL using the configured database settings"
  fi

  psql --no-psqlrc --set ON_ERROR_STOP=1 --tuples-only --no-align \
    --dbname postgres --username "${DB_USER}" --host "${DB_HOST}" --port "${DB_PORT}" \
    --command 'SELECT 1' >/dev/null 2>&1 \
    || fail "cannot connect to PostgreSQL at ${DB_HOST}:${DB_PORT} as ${DB_USER}"

  printf 'Creating local PostgreSQL database %s...\n' "${DB_NAME}"
  createdb --username "${DB_USER}" --host "${DB_HOST}" --port "${DB_PORT}" "${DB_NAME}" \
    || fail "failed to create PostgreSQL database ${DB_NAME}"
}

ensure_web_dependencies() {
  if [ ! -f "${ROOT_DIR}/web/node_modules/vite/bin/vite.js" ]; then
    printf 'Installing web dependencies...\n'
    npm --prefix "${ROOT_DIR}/web" ci --no-audit --no-fund
  fi
}

ensure_port_free() {
  local label="$1"
  local port="$2"

  command -v lsof >/dev/null 2>&1 || return
  if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
    printf 'Port %s is already in use (%s).\n' "${port}" "${label}" >&2
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >&2 || true
    exit 1
  fi
}

print_configuration() {
  printf 'API=%s\n' "${API_URL}"
  printf 'WORKER=%s\n' "${WORKER_URL}"
  printf 'WEB=%s\n' "${WEB_URL}"
}

show_logs() {
  local log_file

  for log_file in "${LOG_DIR}"/*.log; do
    [ -f "${log_file}" ] || continue
    printf '\n----- %s -----\n' "$(basename "${log_file}")" >&2
    tail -n 40 "${log_file}" >&2
  done
}

cleanup() {
  local status=$?

  trap - EXIT INT TERM HUP
  for pid in "${api_pid}" "${worker_pid}" "${web_pid}"; do
    if [ -n "${pid}" ] && kill -0 "${pid}" >/dev/null 2>&1; then
      kill "${pid}" >/dev/null 2>&1 || true
    fi
  done
  wait >/dev/null 2>&1 || true
  exit "${status}"
}

wait_for_service() {
  local name="$1"
  local url="$2"
  local pid="$3"
  local attempt=0

  while [ "${attempt}" -lt 240 ]; do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      printf '%s exited before becoming healthy.\n' "${name}" >&2
      return 1
    fi
    if curl --fail --silent --show-error "${url}" >/dev/null 2>&1; then
      return
    fi
    attempt=$((attempt + 1))
    sleep 0.25
  done

  printf '%s did not become healthy at %s.\n' "${name}" "${url}" >&2
  return 1
}

monitor_services() {
  local pid
  local status

  while :; do
    for pid in "${api_pid}" "${worker_pid}" "${web_pid}"; do
      if ! kill -0 "${pid}" >/dev/null 2>&1; then
        status=0
        wait "${pid}" || status=$?
        return "${status}"
      fi
    done
    sleep 1
  done
}

mode="${1:-start}"
case "${mode}" in
  --help|-h)
    usage
    exit 0
    ;;
  --check)
    preflight
    ensure_database
    print_configuration
    exit 0
    ;;
  start)
    [ "$#" -eq 0 ] || fail "unexpected arguments; run with --help for usage"
    ;;
  *)
    fail "unknown option '$1'; run with --help for usage"
    ;;
esac

preflight
ensure_database
ensure_web_dependencies
ensure_port_free API 8080
ensure_port_free worker 8081
ensure_port_free web 5173

RUN_DIR="$(mktemp -d "${TMP_ROOT%/}/relythra-dev-$(id -u).XXXXXX")"
LOG_DIR="${RUN_DIR}/logs"
mkdir -p "${LOG_DIR}"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

printf 'Building Go services...\n'
go build -o "${RUN_DIR}/relythra-api" "${ROOT_DIR}/cmd/relythra-api"
go build -o "${RUN_DIR}/relythra-worker" "${ROOT_DIR}/cmd/relythra-worker"
go build -o "${RUN_DIR}/relythra-migrate" "${ROOT_DIR}/cmd/relythra-migrate"

printf 'Applying PostgreSQL migrations...\n'
"${RUN_DIR}/relythra-migrate" up

"${RUN_DIR}/relythra-api" >"${LOG_DIR}/api.log" 2>&1 &
api_pid=$!
"${RUN_DIR}/relythra-worker" >"${LOG_DIR}/worker.log" 2>&1 &
worker_pid=$!
(
  cd "${ROOT_DIR}/web"
  exec node node_modules/vite/bin/vite.js --host 127.0.0.1 --port 5173
) >"${LOG_DIR}/web.log" 2>&1 &
web_pid=$!

if ! wait_for_service API "${API_URL}/health/ready" "${api_pid}" ||
  ! wait_for_service worker "${WORKER_URL}/metrics" "${worker_pid}" ||
  ! wait_for_service web "${WEB_URL}/" "${web_pid}"; then
  show_logs
  exit 1
fi

printf '\nRelythra is ready.\n'
printf 'Web:            %s\n' "${WEB_URL}"
printf 'API readiness:  %s/health/ready\n' "${API_URL}"
printf 'Worker metrics: %s/metrics\n' "${WORKER_URL}"
printf 'Logs:           %s\n' "${LOG_DIR}"
printf 'Press Ctrl+C to stop all services.\n\n'

monitor_services
show_logs
exit 1
