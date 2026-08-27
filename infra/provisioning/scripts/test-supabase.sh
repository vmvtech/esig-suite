#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/esig-provisioning-supabase.XXXXXX")
SUPABASE_DB_IMAGE=${SUPABASE_DB_IMAGE:-public.ecr.aws/supabase/postgres:17.6.1.156}
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

database_ready=0
for _ in $(seq 1 30); do
  if docker exec "$DB_CONTAINER" \
    pg_isready -U supabase_admin -d postgres >/dev/null 2>&1; then
    database_ready=1
    break
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
