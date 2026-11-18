#!/usr/bin/env sh
# Start the local dev stack (PostgreSQL + Redis) and wait until both are healthy.
# Usage: sh infra/scripts/dev-up.sh        (run from the repo root)
# Stop:  docker compose -f infra/compose/docker-compose.dev.yml down   (keeps data)
set -eu

COMPOSE_FILE="infra/compose/docker-compose.dev.yml"
ENV_ARGS=""
if [ -f .env ]; then
  ENV_ARGS="--env-file .env"
fi

# shellcheck disable=SC2086
docker compose $ENV_ARGS -f "$COMPOSE_FILE" up -d --wait --wait-timeout 90
# shellcheck disable=SC2086
docker compose $ENV_ARGS -f "$COMPOSE_FILE" ps
