#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

MAX_WAIT_SECONDS="${MAX_WAIT_SECONDS:-120}"
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"

log_step "Waiting for API health: $API_URL/health"
elapsed=0
while (( elapsed < MAX_WAIT_SECONDS )); do
	response="$(curl -sS "$API_URL/health" || true)"
	if [[ -n "$response" ]] && [[ "$(json_get "$response" ".status" || true)" == "ok" ]]; then
		json_pretty "$response"
		log_step "API is healthy"
		exit 0
	fi
	sleep "$SLEEP_SECONDS"
	elapsed=$((elapsed + SLEEP_SECONDS))
done

echo "API did not become healthy within ${MAX_WAIT_SECONDS}s" >&2
exit 1
