#!/usr/bin/env bash
set -euo pipefail

URL="${1:-http://localhost:3000/api/health}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-60}"
SLEEP_SECS="${SLEEP_SECS:-1}"

echo "Waiting for $URL to become healthy (max ${MAX_ATTEMPTS} attempts)..."

for i in $(seq 1 "$MAX_ATTEMPTS"); do
  if curl -fsS "$URL" > /dev/null 2>&1; then
    echo "Healthy after ${i} attempts."
    exit 0
  fi
  sleep "$SLEEP_SECS"
done

echo "Service did not become healthy within ${MAX_ATTEMPTS} attempts. Logs:"
docker compose logs --tail 50 || true
exit 1
