#!/usr/bin/env bash
# Only this script's fresh project and temporary credentials are destroyed.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/relythra-demo-smoke.XXXXXX")"
chmod 700 "$temp_dir"
project="relythra-demo-smoke-$$"
for name in postgres_password management_token demo_owner_password demo_reader_password observability_token grafana_admin_password grafana_webhook_secret; do
  (umask 077; od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$temp_dir/$name")
done
export RELYTHRA_POSTGRES_PASSWORD_FILE="$temp_dir/postgres_password"
export RELYTHRA_MANAGEMENT_TOKEN_FILE="$temp_dir/management_token"
export DEMO_OWNER_PASSWORD_FILE="$temp_dir/demo_owner_password"
export DEMO_READER_PASSWORD_FILE="$temp_dir/demo_reader_password"
export DEMO_OBSERVABILITY_TOKEN_FILE="$temp_dir/observability_token"
export DEMO_GRAFANA_PASSWORD_FILE="$temp_dir/grafana_admin_password"
export DEMO_GRAFANA_WEBHOOK_SECRET_FILE="$temp_dir/grafana_webhook_secret"
export RELYTHRA_API_PORT=28080 RELYTHRA_WORKER_PORT=28081 RELYTHRA_WEB_PORT=23000 RELYTHRA_POSTGRES_PORT=25432
export DEMO_ORDERS_PORT=28090 DEMO_PROMETHEUS_PORT=29090 DEMO_LOKI_PORT=23100 DEMO_GRAFANA_PORT=23001
export DEMO_ENABLE_FAULTS=false DEMO_ORDERS_RELEASE=baseline DEMO_INVENTORY_RELEASE=baseline
COMPOSE=(docker compose --env-file /dev/null --project-name "$project" --file deploy/compose/compose.yaml --file deploy/compose/demo.yaml)
stage="compose configuration validation"
cleanup() {
  local status=$?
  trap - EXIT
  if [ "$status" -ne 0 ]; then
    local artifact_root="${RELYTHRA_DEMO_ARTIFACT_DIR:-${TMPDIR:-/tmp}/relythra-demo-smoke-artifacts}"
    local artifact_dir="$artifact_root/$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM"
    if ! (umask 077; python3 scripts/demo_artifacts.py "$project" "$artifact_dir" "$temp_dir" "$stage" "$status"); then
      printf 'Could not save demo smoke diagnostics under %s\n' "$artifact_root" >&2
    fi
  fi
  if ! "${COMPOSE[@]}" down --volumes --remove-orphans; then
    if [ "$status" -eq 0 ]; then
      status=1
      local artifact_root="${RELYTHRA_DEMO_ARTIFACT_DIR:-${TMPDIR:-/tmp}/relythra-demo-smoke-artifacts}"
      local artifact_dir="$artifact_root/$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM"
      if ! (umask 077; python3 scripts/demo_artifacts.py "$project" "$artifact_dir" "$temp_dir" "cleanup" "$status"); then
        printf 'Could not save demo smoke diagnostics under %s\n' "$artifact_root" >&2
      fi
    fi
  fi
  rm -rf "$temp_dir"
  exit "$status"
}
trap cleanup EXIT
stage="render and verify Compose configuration"
"${COMPOSE[@]}" config --format json > "$temp_dir/compose.json"
python3 scripts/demo-assert.py config "$temp_dir/compose.json"
stage="build and start demo services"
"${COMPOSE[@]}" up --build --wait --wait-timeout 240
stage="verify observability token is available to the Worker"
"${COMPOSE[@]}" exec -T worker sh -c '
  cmp /run/secrets/observability_token /run/relythra-secrets/observability_token
  test "$(stat -c %a /run/relythra-secrets/observability_token)" = 440
  test "$(stat -c %u:%g /run/relythra-secrets/observability_token)" = 10001:10001
  su-exec relythra test -r /run/relythra-secrets/observability_token
'
stage="seed isolated Grafana webhook project and service"
"${COMPOSE[@]}" exec -T postgres psql -U relythra -d relythra -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO projects (slug, name) VALUES ('relythra-demo', 'Relythra isolated demo')
ON CONFLICT (slug) DO NOTHING;
INSERT INTO services (project_id, slug, name)
SELECT id, 'inventory', 'Inventory demo service' FROM projects WHERE slug = 'relythra-demo'
ON CONFLICT (project_id, slug) DO NOTHING;
INSERT INTO services (project_id, slug, name)
SELECT id, 'orders', 'Orders demo service' FROM projects WHERE slug = 'relythra-demo'
ON CONFLICT (project_id, slug) DO NOTHING;
SQL
stage="create isolated Inventory Prometheus mapping"
project_id="$("${COMPOSE[@]}" exec -T postgres psql -U relythra -d relythra -Atc "SELECT id FROM projects WHERE slug='relythra-demo'")"
service_id="$("${COMPOSE[@]}" exec -T postgres psql -U relythra -d relythra -Atc "SELECT s.id FROM services s JOIN projects p ON p.id=s.project_id WHERE p.slug='relythra-demo' AND s.slug='inventory'")"
test -n "$project_id" && test -n "$service_id"
python3 scripts/demo-assert.py configure-prometheus-mapping "$project_id" "$service_id"
stage="baseline telemetry assertions"
python3 scripts/demo-assert.py healthy
stage="prime Inventory latency on the Worker range-query grid"
python3 scripts/demo-assert.py prime-prometheus-latency
stage="Grafana HMAC webhook delivery assertions"
webhook_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
"${COMPOSE[@]}" stop inventory
investigation_id=""
for attempt in $(seq 1 60); do
  investigation_id="$("${COMPOSE[@]}" exec -T postgres psql -U relythra -d relythra -Atc "SELECT i.id FROM alert_deliveries d JOIN alerts a ON a.id=d.alert_id JOIN projects p ON p.id=a.project_id JOIN services s ON s.id=a.service_id JOIN incidents n ON n.alert_id=a.id JOIN investigations i ON i.incident_id=n.id WHERE p.slug='relythra-demo' AND s.slug='inventory' AND d.delivery_status='FIRING' AND d.mapping_status='MATCHED' AND d.received_at >= '$webhook_started_at'::timestamptz ORDER BY d.received_at LIMIT 1")"
  if [ -n "$investigation_id" ]; then break; fi
  sleep 2
done
test -n "$investigation_id" || { printf 'Grafana alert did not reach Relythra via signed webhook.\n' >&2; exit 1; }
python3 scripts/demo-assert.py grafana-delivery "$investigation_id" FIRING
stage="Worker Prometheus Evidence timeline assertion"
python3 scripts/demo-assert.py prometheus-evidence "$investigation_id"
"${COMPOSE[@]}" start --wait inventory
stage="Grafana resolved webhook and evidence assertions"
python3 scripts/demo-assert.py grafana-delivery "$investigation_id" RESOLVED
python3 scripts/demo-assert.py healthy
stage="deploy slow SQL fault fixture"
DEMO_ENABLE_FAULTS=true \
  DEMO_INVENTORY_RELEASE=slow-sql-fault \
  "${COMPOSE[@]}" up --force-recreate --no-build --no-deps --wait --wait-timeout 120 inventory
stage="slow SQL fault telemetry assertions"
python3 scripts/demo-assert.py slow-sql-fault
stage="restore baseline inventory fixture"
DEMO_ENABLE_FAULTS=false \
  DEMO_INVENTORY_RELEASE=baseline \
  "${COMPOSE[@]}" up --force-recreate --no-deps --wait --wait-timeout 120 inventory
stage="slow SQL recovery telemetry assertions"
python3 scripts/demo-assert.py slow-sql-recovered
stage="container identity and database isolation assertions"
for service in api inventory orders; do
  test "$("${COMPOSE[@]}" exec -T "$service" awk '$1 == "Uid:" { print $2 }' /proc/1/status)" = "10001"
done
test "$("${COMPOSE[@]}" exec -T api stat -c '%a:%u:%g' /run/relythra-secrets/grafana_webhook_secret)" = "440:10001:10001"
test "$("${COMPOSE[@]}" exec -T grafana awk '$1 == "Uid:" { print $2 }' /proc/1/status)" = "472"
# SQL grants, not only default_transaction_read_only, must prevent writes.
"${COMPOSE[@]}" exec -T demo-postgres psql -U demo_owner -d demo -v ON_ERROR_STOP=1 <<'SQL'
SET ROLE demo_reader;
SET default_transaction_read_only = off;
DO $$ BEGIN
  IF has_table_privilege(current_user, 'demo_stock', 'INSERT,UPDATE,DELETE,TRUNCATE') THEN
    RAISE EXCEPTION 'demo_reader has write privileges';
  END IF;
END $$;
SELECT quantity FROM demo_stock WHERE sku = 'demo-sku';
SQL
# Real login and cross-database isolation: demo_reader is not a control-plane role.
"${COMPOSE[@]}" exec -T demo-postgres sh -c 'PGPASSWORD="$(cat /run/secrets/demo_reader_password)" psql -h 127.0.0.1 -U demo_reader -d demo -v ON_ERROR_STOP=1 -c "SELECT quantity FROM demo_stock"'
if "${COMPOSE[@]}" exec -T postgres psql -U relythra -d relythra -tAc "SELECT 1 FROM pg_roles WHERE rolname='demo_reader'" | grep -q 1; then
  printf 'Demo role leaked into control database.\n' >&2; exit 1
fi
# Missing schema must fail readiness without silently resetting the persisted volume.
"${COMPOSE[@]}" exec -T demo-postgres psql -U demo_owner -d demo -v ON_ERROR_STOP=1 -c 'ALTER TABLE demo_stock RENAME TO demo_stock_saved'
python3 scripts/demo-assert.py dependency-down
"${COMPOSE[@]}" exec -T demo-postgres psql -U demo_owner -d demo -v ON_ERROR_STOP=1 -c 'ALTER TABLE demo_stock_saved RENAME TO demo_stock'
stage="schema dependency recovery assertions"
python3 scripts/demo-assert.py recovered
"${COMPOSE[@]}" stop demo-postgres
stage="database outage and reconnection assertions"
python3 scripts/demo-assert.py dependency-down
"${COMPOSE[@]}" start --wait demo-postgres
# The services reconnect without a restart and the seed is retained.
python3 scripts/demo-assert.py recovered
stage="service restart and final health assertions"
"${COMPOSE[@]}" restart inventory orders observability-gateway grafana
"${COMPOSE[@]}" up --wait --wait-timeout 120 --no-build
python3 scripts/demo-assert.py healthy
# Exact image IDs for local evidence; not claims of provenance/SBOM or deployment.
"${COMPOSE[@]}" images
printf 'Demo smoke passed: real call chain, telemetry, read-only access, isolation, restart and recovery.\n'
