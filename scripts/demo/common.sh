#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:8000}"
DEMO_DIR="${DEMO_DIR:-.demo}"
CTX_FILE="${CTX_FILE:-$DEMO_DIR/context.json}"

mkdir -p "$DEMO_DIR"

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Missing required command: $1" >&2
		exit 1
	fi
}

require_cmd curl
require_cmd python3

log_step() {
	printf "\n==> %s\n" "$*"
}

HTTP_STATUS=""
HTTP_BODY=""

request_json() {
	local method="$1"
	local path="$2"
	local token="${3:-}"
	local body="${4:-}"
	local response
	local -a args

	args=(-sS -X "$method" "$API_URL$path" -H "Content-Type: application/json")
	if [[ -n "$token" ]]; then
		args+=(-H "Authorization: Bearer $token")
	fi
	if [[ -n "$body" ]]; then
		args+=(-d "$body")
	fi

	response="$(curl "${args[@]}" -w $'\n%{http_code}')"
	HTTP_STATUS="${response##*$'\n'}"
	HTTP_BODY="${response%$'\n'*}"
}

expect_status() {
	local expected="$1"
	if [[ "$HTTP_STATUS" != "$expected" ]]; then
		echo "Unexpected status: got $HTTP_STATUS, expected $expected" >&2
		json_pretty "$HTTP_BODY" >&2
		exit 1
	fi
}

expect_error() {
	local expected_status="$1"
	local expected_code="$2"
	local actual_code

	expect_status "$expected_status"
	actual_code="$(json_get "$HTTP_BODY" ".error_code" || true)"
	if [[ "$actual_code" != "$expected_code" ]]; then
		echo "Unexpected error_code: got $actual_code, expected $expected_code" >&2
		json_pretty "$HTTP_BODY" >&2
		exit 1
	fi
}

pretty_last() {
	json_pretty "$HTTP_BODY"
}

ctx_get() {
	local key="$1"
	if [[ ! -f "$CTX_FILE" ]]; then
		echo "Context file not found: $CTX_FILE. Run scripts/demo/e2e.sh first." >&2
		exit 1
	fi
	json_get_file "$CTX_FILE" "$key"
}

json_pretty() {
	local json="$1"
	python3 - "$json" <<'PY'
import json
import sys

raw = sys.argv[1].strip()
if not raw:
    print("")
    raise SystemExit(0)
try:
    parsed = json.loads(raw)
    print(json.dumps(parsed, indent=2, ensure_ascii=False))
except Exception:
    print(raw)
PY
}

json_get() {
	local json="$1"
	local path="$2"
	python3 - "$path" "$json" <<'PY'
import json
import sys

path = sys.argv[1]
raw = sys.argv[2]
data = json.loads(raw)

def walk(obj, key_path):
    if key_path in ("", "."):
        return obj
    if key_path.startswith("."):
        key_path = key_path[1:]
    current = obj
    for part in key_path.split("."):
        if not part:
            continue
        if "[" in part and part.endswith("]"):
            key, index_part = part[:-1].split("[", 1)
            if key:
                current = current[key]
            current = current[int(index_part)]
        else:
            current = current[part]
    return current

value = walk(data, path)
if value is None:
    print("null")
elif isinstance(value, (dict, list)):
    print(json.dumps(value, separators=(",", ":"), ensure_ascii=False))
else:
    print(value)
PY
}

json_get_file() {
	local file="$1"
	local path="$2"
	python3 - "$file" "$path" <<'PY'
import json
import sys

file_path = sys.argv[1]
path = sys.argv[2]

with open(file_path, "r", encoding="utf-8") as f:
    data = json.load(f)

def walk(obj, key_path):
    if key_path in ("", "."):
        return obj
    if key_path.startswith("."):
        key_path = key_path[1:]
    current = obj
    for part in key_path.split("."):
        if not part:
            continue
        if "[" in part and part.endswith("]"):
            key, index_part = part[:-1].split("[", 1)
            if key:
                current = current[key]
            current = current[int(index_part)]
        else:
            current = current[part]
    return current

value = walk(data, path)
if value is None:
    print("null")
elif isinstance(value, (dict, list)):
    print(json.dumps(value, separators=(",", ":"), ensure_ascii=False))
else:
    print(value)
PY
}
