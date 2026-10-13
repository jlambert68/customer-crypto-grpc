#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v curl >/dev/null 2>&1; then
  printf 'ERROR: curl is required for the REST integration checks\n'
  exit 1
fi
rm -rf demo.db identities
mkdir -p identities
(go run ./cmd/bootstrap -db demo.db -identities identities)
server_bin=$(mktemp /tmp/customer-crypto-server.XXXXXX)
web_bin=$(mktemp /tmp/customer-crypto-web.XXXXXX)
pid=
web_pid=
cleanup() {
  if [[ -n "$web_pid" ]]; then
    kill "$web_pid" 2>/dev/null || true
    wait "$web_pid" 2>/dev/null || true
  fi
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -f "$server_bin" "$web_bin"
}
trap cleanup EXIT
go build -o "$server_bin" ./cmd/server
go build -o "$web_bin" ./cmd/web
"$server_bin" -db demo.db > /tmp/customer-crypto-server.log 2>&1 &
pid=$!
sleep 3
if ! kill -0 "$pid" 2>/dev/null; then
  printf 'ERROR: demo server failed to start:\n'
  sed -n '1,120p' /tmp/customer-crypto-server.log
  exit 1
fi
go run ./cmd/rotation -action seed
"$web_bin" -grpc 127.0.0.1:50051 -listen 127.0.0.1:8080 -identities identities > /tmp/customer-crypto-web.log 2>&1 &
web_pid=$!
for _ in {1..30}; do
  if curl -fsS http://127.0.0.1:8080/api/v1/health >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
if ! kill -0 "$web_pid" 2>/dev/null || ! curl -fsS http://127.0.0.1:8080/api/v1/health >/dev/null; then
  printf 'ERROR: REST and web client failed to start:\n'
  sed -n '1,160p' /tmp/customer-crypto-web.log
  exit 1
fi
index=$(curl -fsS http://127.0.0.1:8080/)
if [[ "$index" != *"Customer Crypto Console"* ]]; then
  printf 'ERROR: web client index did not contain the expected title\n'
  exit 1
fi
config=$(curl -fsS http://127.0.0.1:8080/api/v1/config)
if [[ "$config" != *'"id":"customer1"'* || "$config" != *'"id":"backoffice2"'* || "$config" == *'"token"'* || "$config" == *'"secret"'* ]]; then
  printf 'ERROR: REST configuration is incomplete or exposes credentials:\n%s\n' "$config"
  exit 1
fi
app_js=$(curl -fsS http://127.0.0.1:8080/app.js)
if [[ "$app_js" != *"X-Demo-Identity"* ]]; then
  printf 'ERROR: web client JavaScript was not served correctly\n'
  exit 1
fi
printf '\nTesting REST API and web client at http://127.0.0.1:8080\n'

rest_call() {
  local method=$1
  local who=$2
  local obj=$3
  local payload=${4-}
  local args=(-sS -X "$method" -H "Accept: application/json" -H "X-Demo-Identity: $who")
  if [[ -n "$payload" ]]; then
    args+=(-H "Content-Type: application/json" --data "$payload")
  fi
  curl "${args[@]}" -w $'\n%{http_code}' "http://127.0.0.1:8080/api/v1/records/$obj"
}

expected_access() {
  case "$1:$2" in
    customer1:C001|customer2:C002|customer3:C003|backoffice1:C001|backoffice1:C002|backoffice2:C002|backoffice2:C003) return 0 ;;
    *) return 1 ;;
  esac
}

run_access_matrix() {
  local round=$1
  local who obj response status body
  printf '\n%s\n' "$round"
  for who in customer1 customer2 customer3 backoffice1 backoffice2; do
    for obj in C001 C002 C003; do
      response=$(rest_call GET "$who" "$obj")
      status=${response##*$'\n'}
      body=${response%$'\n'*}
      if expected_access "$who" "$obj"; then
        if [[ "$status" != "200" ]]; then
          printf 'ERROR: expected %s to read %s, got HTTP %s:\n%s\n' "$who" "$obj" "$status" "$body"
          exit 1
        fi
        if [[ "$round" == "REST access matrix after customer update" && "$obj" == "C001" && "$body" != *'"city":"Gothenburg"'* ]]; then
          printf 'ERROR: %s read C001 without the updated city:\n%s\n' "$who" "$body"
          exit 1
        fi
        printf 'ALLOW %s -> %s: HTTP %s\n' "$who" "$obj" "$status"
      else
        if [[ "$status" != "403" ]]; then
          printf 'ERROR: expected %s to be denied access to %s, got HTTP %s:\n%s\n' "$who" "$obj" "$status" "$body"
          exit 1
        fi
        if [[ "$body" != *"access denied"* ]]; then
          printf 'ERROR: %s -> %s failed for an unexpected reason:\n%s\n' "$who" "$obj" "$body"
          exit 1
        fi
        printf 'DENY  %s -> %s: HTTP %s as expected\n' "$who" "$obj" "$status"
      fi
    done
  done
}

run_access_matrix "Initial REST access matrix"

response=$(rest_call PATCH backoffice1 C001 '{"changes":{"city":"ShouldNotWork"}}')
status=${response##*$'\n'}
body=${response%$'\n'*}
if [[ "$status" != "403" || "$body" != *"only the customer who owns the record can update it"* ]]; then
  printf 'ERROR: backoffice1 update returned HTTP %s:\n%s\n' "$status" "$body"
  exit 1
fi
printf '\nDENY  backoffice1 update C001: HTTP 403 owner-only update enforced\n'

response=$(rest_call PATCH customer1 C001 '{"changes":{"city":"Gothenburg","notes":"Updated through the REST web client"}}')
status=${response##*$'\n'}
body=${response%$'\n'*}
if [[ "$status" != "200" || "$body" != *'"version":2'* || "$body" != *'"city":"Gothenburg"'* ]]; then
  printf 'ERROR: customer1 update returned HTTP %s:\n%s\n' "$status" "$body"
  exit 1
fi
printf 'ALLOW customer1 update C001: HTTP 200, encrypted version 2 created with a fresh DEK\n'

run_access_matrix "REST access matrix after customer update"
if ! grep -q 'msg="record updated"' /tmp/customer-crypto-web.log || ! grep -q 'request_id=req-' /tmp/customer-crypto-web.log; then
  printf 'ERROR: structured REST console logging was not produced\n'
  exit 1
fi
printf '\nIntegration demo passed\n'
