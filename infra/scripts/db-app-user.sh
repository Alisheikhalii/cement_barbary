#!/bin/sh
# Enables the bitabar_app runtime login on the LOCAL dev compose stack.
# The password comes from APP_DB_PASSWORD (environment or .env) and reaches
# psql through a variable (:'pw'), never interpolated into SQL by hand and
# never printed. Refuses placeholder/empty passwords.
set -eu
set +x

get_env() { grep -E "^$1=" .env 2>/dev/null | head -n 1 | cut -d= -f2-; }

APP_DB_PASSWORD=${APP_DB_PASSWORD:-$(get_env APP_DB_PASSWORD)}
if [ -z "$APP_DB_PASSWORD" ] || [ "$APP_DB_PASSWORD" = "CHANGE_ME_APP" ]; then
  echo "Refusing: APP_DB_PASSWORD is empty or still the placeholder." >&2
  echo "Set a real password in .env (APP_DB_PASSWORD=...) and re-run." >&2
  exit 1
fi

POSTGRES_USER=${POSTGRES_USER:-$(get_env POSTGRES_USER)}
POSTGRES_DB=${POSTGRES_DB:-$(get_env POSTGRES_DB)}
POSTGRES_USER=${POSTGRES_USER:-bitabar}
POSTGRES_DB=${POSTGRES_DB:-bitabar}

COMPOSE="docker compose -f infra/compose/docker-compose.dev.yml"
if [ -f .env ]; then
  COMPOSE="docker compose --env-file .env -f infra/compose/docker-compose.dev.yml"
fi

# shellcheck disable=SC2086
$COMPOSE exec -T postgres psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v pw="$APP_DB_PASSWORD" <<'SQL'
ALTER ROLE bitabar_app LOGIN PASSWORD :'pw';
SQL

echo "bitabar_app login enabled on the local dev stack (password not shown)."
