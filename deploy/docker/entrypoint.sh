#!/bin/sh
set -eu

source_database_secret=/run/secrets/postgres_password
runtime_database_secret=/run/relythra-secrets/postgres_password
source_management_secret=/run/secrets/management_token
runtime_management_secret=/run/relythra-secrets/management_token
source_grafana_secret=/run/secrets/grafana_webhook_secret
runtime_grafana_secret=/run/relythra-secrets/grafana_webhook_secret
source_observability_secret=/run/secrets/observability_token
runtime_observability_secret=/run/relythra-secrets/observability_token

if [ "${RELYTHRA_DATABASE_PASSWORD_REF:-}" = "file:${source_database_secret}" ] ||
   [ "${RELYTHRA_ADMIN_TOKEN_REF:-}" = "file:${source_management_secret}" ] ||
   [ "${RELYTHRA_GRAFANA_WEBHOOK_SECRET_REF:-}" = "file:${source_grafana_secret}" ] ||
   [ -f "${source_observability_secret}" ]; then
  mkdir -p /run/relythra-secrets
  chown root:relythra /run/relythra-secrets
  chmod 0710 /run/relythra-secrets
fi

if [ -f "${source_observability_secret}" ]; then
  cp "${source_observability_secret}" "${runtime_observability_secret}"
  chown relythra:relythra "${runtime_observability_secret}"
  chmod 0440 "${runtime_observability_secret}"
fi

if [ "${RELYTHRA_DATABASE_PASSWORD_REF:-}" = "file:${source_database_secret}" ]; then
  cp "${source_database_secret}" "${runtime_database_secret}"
  chown relythra:relythra "${runtime_database_secret}"
  chmod 0440 "${runtime_database_secret}"
  export RELYTHRA_DATABASE_PASSWORD_REF="file:${runtime_database_secret}"
fi

if [ "${RELYTHRA_ADMIN_TOKEN_REF:-}" = "file:${source_management_secret}" ]; then
  cp "${source_management_secret}" "${runtime_management_secret}"
  chown relythra:relythra "${runtime_management_secret}"
  chmod 0440 "${runtime_management_secret}"
  export RELYTHRA_ADMIN_TOKEN_REF="file:${runtime_management_secret}"
fi

if [ "${RELYTHRA_GRAFANA_WEBHOOK_SECRET_REF:-}" = "file:${source_grafana_secret}" ]; then
  cp "${source_grafana_secret}" "${runtime_grafana_secret}"
  chown relythra:relythra "${runtime_grafana_secret}"
  chmod 0440 "${runtime_grafana_secret}"
  export RELYTHRA_GRAFANA_WEBHOOK_SECRET_REF="file:${runtime_grafana_secret}"
fi

if [ -d /var/log/demo ]; then
  chown relythra:relythra /var/log/demo
  chmod 0750 /var/log/demo
fi

exec su-exec relythra /usr/local/bin/relythra "$@"
