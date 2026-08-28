#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/esig-provisioning-supabase.XXXXXX")
# Pinned by digest (resolved via `docker manifest inspect ... -v`, 2026-08-27) so
# a re-tagged/mutated upstream image can't silently change what CI runs against.
SUPABASE_DB_IMAGE=${SUPABASE_DB_IMAGE:-public.ecr.aws/supabase/postgres:17.6.1.156@sha256:665efa7e234a3c324718fd2b7fbbaaaf7263f2565bc2e8fce8555c4def4c4985}
DB_CONTAINER="esig-provisioning-db-$(basename "$TMP_ROOT" | tr -cd '[:alnum:]_-')"

cleanup() {
  docker rm -f "$DB_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

docker run --detach \
  --name "$DB_CONTAINER" \
  --network none \
  --env POSTGRES_HOST_AUTH_METHOD=trust \
  "$SUPABASE_DB_IMAGE" >/dev/null

# The supabase image starts postgres, runs init, then RESTARTS it — a single
# pg_isready success can land in the pre-restart window, after which the very
# next connection fails with "the database system is shutting down" (seen live:
# CI run 33186318424). Readiness therefore requires THREE consecutive
# one-second-apart successes of a real query, not one probe.
database_ready=0
consecutive=0
for _ in $(seq 1 60); do
  # `select 1` is not enough: the image's own migrations can still be running
  # (locally under amd64 emulation this window is seconds long), and DDL issued
  # then dies inside the image's graphql event trigger with "could not open
  # relation" on graphql.seq_schema_version. Reading that very sequence proves
  # the migration that creates it has completed.
  if docker exec "$DB_CONTAINER" \
    psql -X -U supabase_admin -d postgres -Atc 'select last_value from graphql.seq_schema_version' >/dev/null 2>&1; then
    consecutive=$((consecutive + 1))
    if [[ "$consecutive" -ge 3 ]]; then
      database_ready=1
      break
    fi
  else
    consecutive=0
  fi
  sleep 1
done

if [[ "$database_ready" != 1 ]]; then
  docker logs --tail 100 "$DB_CONTAINER" >&2
  echo "Supabase PostgreSQL test container did not become ready." >&2
  exit 1
fi

run_sql_file() {
  local sql_file=$1
  docker exec -i "$DB_CONTAINER" \
    psql -X -v ON_ERROR_STOP=1 -U supabase_admin -d postgres < "$sql_file"
}

run_sql_file "$ROOT_DIR/infra/provisioning/test/supabase-db-prelude.sql"
for migration in "$ROOT_DIR"/migrations/000{1,2,3,4}_*.sql; do
  run_sql_file "$migration"
done
run_sql_file "$ROOT_DIR/infra/provisioning/test/cloud-tenants.pgtap.sql"
