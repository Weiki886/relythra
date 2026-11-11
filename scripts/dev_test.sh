#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_ROOT="$(mktemp -d)"
TEST_TMP="${TEST_ROOT}/tmp"
mkdir -p "${TEST_TMP}"
trap 'rm -rf "${TEST_ROOT}"' EXIT

go() {
  printf 'mocked Go build failure\n' >&2
  return 23
}

npm() { return 0; }
node() { return 0; }
curl() { return 0; }
psql() { return 0; }

lsof() {
  local arg
  for arg in "$@"; do
    if [ "${arg}" = "-iTCP:${MOCK_LSOF_BUSY_PORT:-}" ]; then
      printf 'mock listener on port %s\n' "${MOCK_LSOF_BUSY_PORT}"
      return 0
    fi
  done
  return 1
}

export -f go npm node curl psql lsof

legacy_dir="${TEST_TMP}/relythra-dev-$(id -u)"
mkdir -p "${legacy_dir}/logs"
printf 'preserve me\n' >"${legacy_dir}/logs/previous.log"

if output="$(TMPDIR="${TEST_TMP}" RELYTHRA_DATABASE_URL='postgres://test@127.0.0.1:5432/relythra?sslmode=disable' \
  "${ROOT_DIR}/scripts/dev.sh" --check 2>&1)"; then
  case "${output}" in
    *'http://127.0.0.1:5173'*) ;;
    *) printf 'check mode did not print the Web URL:\n%s\n' "${output}" >&2; exit 1 ;;
  esac
else
  printf 'check mode failed unexpectedly:\n%s\n' "${output}" >&2
  exit 1
fi

if [ "$(find "${TEST_TMP}" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d '[:space:]')" -ne 1 ]; then
  printf 'check mode created a runtime directory\n' >&2
  exit 1
fi

if output="$(TMPDIR="${TEST_TMP}" RELYTHRA_DATABASE_URL='postgres://test@127.0.0.1:5432/relythra?sslmode=disable' \
  "${ROOT_DIR}/scripts/dev.sh" 2>&1)"; then
  printf 'startup unexpectedly succeeded with a failing Go build\n' >&2
  exit 1
fi
case "${output}" in
  *'mocked Go build failure'*) ;;
  *) printf 'startup failed for an unexpected reason:\n%s\n' "${output}" >&2; exit 1 ;;
esac

if [ "$(<"${legacy_dir}/logs/previous.log")" != 'preserve me' ]; then
  printf 'startup modified data in a prior run directory\n' >&2
  exit 1
fi

runtime_dirs="$(find "${TEST_TMP}" -mindepth 1 -maxdepth 1 -type d -name "relythra-dev-$(id -u).*" | wc -l | tr -d '[:space:]')"
if [ "${runtime_dirs}" -ne 1 ]; then
  printf 'startup created %s unique runtime directories, want 1\n' "${runtime_dirs}" >&2
  exit 1
fi

if output="$(TMPDIR="${TEST_TMP}" MOCK_LSOF_BUSY_PORT=8080 \
  RELYTHRA_DATABASE_URL='postgres://test@127.0.0.1:5432/relythra?sslmode=disable' \
  "${ROOT_DIR}/scripts/dev.sh" 2>&1)"; then
  printf 'startup unexpectedly succeeded with port 8080 occupied\n' >&2
  exit 1
fi
case "${output}" in
  *'Port 8080 is already in use'*'mock listener on port 8080'*) ;;
  *) printf 'port conflict was not reported clearly:\n%s\n' "${output}" >&2; exit 1 ;;
esac
case "${output}" in
  *'mocked Go build failure'*) printf 'startup built services before port preflight completed\n' >&2; exit 1 ;;
esac

printf 'Local development startup checks passed.\n'
