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
if [[ "$index" != *"Customer Crypto Console"* || "$index" != *"Disable server read authorization"* || "$index" != *"What is the rotation service used for?"* || "$index" != *"The long-lived server and client scalar shares do not rotate"* || "$index" != *"One locked record, several named envelopes"* || "$index" != *"An envelope never contains customer data"* || "$index" != *"Follow only the matching envelope"* || "$index" != *"Show the cryptographic names behind the picture"* || "$index" != *"Follow one request from ciphertext to plaintext"* || "$index" != *"Compute the server’s partial point"* || "$index" != *"Database stores"* || "$index" != *"After client-side decryption"* || "$index" != *"One DEK, wrapped separately for every recipient"* ]]; then
  printf 'ERROR: web client index did not contain the expected authorization, process, and encryption controls\n'
  exit 1
fi
config=$(curl -fsS http://127.0.0.1:8080/api/v1/config)
if [[ "$config" != *'"id":"customer1"'* || "$config" != *'"id":"backoffice2"'* || "$config" != *'"id":"rotation","label":"Rotation service (privileged)","role":"rotation","read":["C001","C002","C003"],"update":[]'* || "$config" == *'"token"'* || "$config" == *'"secret"'* ]]; then
  printf 'ERROR: REST configuration is incomplete or exposes credentials:\n%s\n' "$config"
  exit 1
fi
app_js=$(curl -fsS http://127.0.0.1:8080/app.js)
if [[ "$app_js" != *"X-Demo-Identity"* || "$app_js" != *"X-Demo-Read-Authorization"* || "$app_js" != *"wrapped_dek_hex"* || "$app_js" != *"showEnvelopeVisual"* || "$app_js" != *"showProcessTrace"* || "$app_js" != *"server_partial_point_hex"* ]]; then
  printf 'ERROR: web client JavaScript was not served correctly\n'
  exit 1
fi
app_css=$(curl -fsS http://127.0.0.1:8080/app.css)
if [[ "$app_css" != *".envelope-board"* || "$app_css" != *".envelope-recipient.selected"* || "$app_css" != *".envelope-unlock-node.blocked"* ]]; then
  printf 'ERROR: envelope visualizer styles were not served correctly\n'
  exit 1
fi
printf '\nTesting REST API and web client at http://127.0.0.1:8080\n'

rest_call() {
  local method=$1
  local who=$2
  local obj=$3
  local payload=${4-}
  local read_authorization=${5-}
  local args=(-sS -X "$method" -H "Accept: application/json" -H "X-Demo-Identity: $who")
  if [[ -n "$payload" ]]; then
    args+=(-H "Content-Type: application/json" --data "$payload")
  fi
  if [[ "$read_authorization" == "disabled" ]]; then
    args+=(-H "X-Demo-Read-Authorization: disabled")
  fi
  curl "${args[@]}" -w $'\n%{http_code}' "http://127.0.0.1:8080/api/v1/records/$obj"
}

expected_access() {
  case "$1:$2" in
    customer1:C001|customer2:C002|customer3:C003|backoffice1:C001|backoffice1:C002|backoffice2:C002|backoffice2:C003|rotation:C001|rotation:C002|rotation:C003) return 0 ;;
    *) return 1 ;;
  esac
}

run_access_matrix() {
  local round=$1
  local who obj response status body
  printf '\n%s\n' "$round"
  for who in customer1 customer2 customer3 backoffice1 backoffice2 rotation; do
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
        if [[ "$body" != *'"process_trace":{"status":"completed"'* || "$body" != *'"authenticated":true'* || "$body" != *'"database_read":true'* ]]; then
          printf 'ERROR: %s -> %s did not return a completed educational process trace:\n%s\n' "$who" "$obj" "$body"
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

printf '\nTesting ciphertext exposure with server read authorization disabled\n'
response=$(rest_call GET customer1 C002 '' disabled)
status=${response##*$'\n'}
body=${response%$'\n'*}
if [[ "$status" != "200" || "$body" != *'"authorization_mode":"bypassed"'* || "$body" != *'"database_stored":"{'* || "$body" != *'\"Ciphertext\"'* || "$body" != *'"decrypted":false'* || "$body" != *'no recipient envelope'* || "$body" != *'"recipient_envelopes":['* || "$body" != *'"process_trace":{"status":"blocked"'* || "$body" != *'"envelope_found":false'* || "$body" == *'"data":'* || "$body" == *'"dek_hex":'* || "$body" == *'"server_partial_point_hex":'* || "$body" == *'"key_encryption_key_hex":'* ]]; then
  printf 'ERROR: customer1 did not receive locked C002 ciphertext in bypass mode (HTTP %s):\n%s\n' "$status" "$body"
  exit 1
fi
printf 'LOCK  customer1 -> C002: ciphertext returned, plaintext unavailable without an envelope\n'

response=$(rest_call GET customer1 C001 '' disabled)
status=${response##*$'\n'}
body=${response%$'\n'*}
if [[ "$status" != "200" || "$body" != *'"authorization_mode":"bypassed"'* || "$body" != *'"decrypted":true'* || "$body" != *'"customer_id":"C001"'* || "$body" != *'"recipient":"customer1"'* || "$body" != *'"recipient":"backoffice1"'* || "$body" != *'"recipient":"rotation"'* || "$body" != *'"dek_hex":"'* || "$body" != *'"process_trace":{"status":"completed"'* ]]; then
  printf 'ERROR: customer1 could not decrypt its own C001 data in bypass mode (HTTP %s):\n%s\n' "$status" "$body"
  exit 1
fi
c001_dek_before=$(sed -n 's/.*"dek_hex":"\([0-9a-f]\{64\}\)".*/\1/p' <<<"$body")
server_partial=$(sed -n 's/.*"server_partial_point_hex":"\([0-9a-f]\{130\}\)".*/\1/p' <<<"$body")
client_partial=$(sed -n 's/.*"client_partial_point_hex":"\([0-9a-f]\{130\}\)".*/\1/p' <<<"$body")
combined_point=$(sed -n 's/.*"combined_shared_point_hex":"\([0-9a-f]\{130\}\)".*/\1/p' <<<"$body")
kek=$(sed -n 's/.*"key_encryption_key_hex":"\([0-9a-f]\{64\}\)".*/\1/p' <<<"$body")
if [[ ${#c001_dek_before} -ne 64 || ${#server_partial} -ne 130 || ${#client_partial} -ne 130 || ${#combined_point} -ne 130 || ${#kek} -ne 64 ]]; then
  printf 'ERROR: C001 response did not expose the complete derived-value process trace:\n%s\n' "$body"
  exit 1
fi
printf 'ALLOW customer1 -> C001: ciphertext returned; every recipient envelope maps to DEK %s…\n' "${c001_dek_before:0:12}"

response=$(rest_call GET backoffice1 C001)
status=${response##*$'\n'}
body=${response%$'\n'*}
backoffice1_c001_dek=$(sed -n 's/.*"dek_hex":"\([0-9a-f]\{64\}\)".*/\1/p' <<<"$body")
if [[ "$status" != "200" || "$backoffice1_c001_dek" != "$c001_dek_before" ]]; then
  printf 'ERROR: customer1 and backoffice1 did not unwrap the same C001 DEK (HTTP %s):\n%s\n' "$status" "$body"
  exit 1
fi
response=$(rest_call GET rotation C001)
status=${response##*$'\n'}
body=${response%$'\n'*}
rotation_c001_dek=$(sed -n 's/.*"dek_hex":"\([0-9a-f]\{64\}\)".*/\1/p' <<<"$body")
if [[ "$status" != "200" || "$rotation_c001_dek" != "$c001_dek_before" || "$body" != *'"actor":"rotation"'* || "$body" != *'"can_update":false'* ]]; then
  printf 'ERROR: rotation did not read C001 through its own envelope without browser update permission (HTTP %s):\n%s\n' "$status" "$body"
  exit 1
fi
printf 'VERIFY customer1, backoffice1, and rotation independently unwrap the same C001 DEK\n'

response=$(rest_call PATCH backoffice1 C001 '{"changes":{"city":"ShouldNotWork"}}' disabled)
status=${response##*$'\n'}
body=${response%$'\n'*}
if [[ "$status" != "403" || "$body" != *"only the customer who owns the record can update it"* ]]; then
  printf 'ERROR: backoffice1 update returned HTTP %s:\n%s\n' "$status" "$body"
  exit 1
fi
printf '\nDENY  backoffice1 update C001: HTTP 403 owner-only update enforced even with the read bypass header\n'

response=$(rest_call PATCH rotation C001 '{"changes":{"city":"PrivilegedWriteShouldNotWork"}}')
status=${response##*$'\n'}
body=${response%$'\n'*}
if [[ "$status" != "403" || "$body" != *"only the customer who owns the record can update it"* ]]; then
  printf 'ERROR: rotation browser update returned HTTP %s:\n%s\n' "$status" "$body"
  exit 1
fi
printf 'DENY  rotation browser update C001: HTTP 403; maintenance writes stay in the separate rotation workflow\n'

response=$(rest_call PATCH customer1 C001 '{"changes":{"city":"Gothenburg","notes":"Updated through the REST web client"}}')
status=${response##*$'\n'}
body=${response%$'\n'*}
if [[ "$status" != "200" || "$body" != *'"version":2'* || "$body" != *'"city":"Gothenburg"'* || "$body" != *'"dek_hex":"'* || "$body" != *'"operation":"update"'* || "$body" != *'"status":"completed"'* ]]; then
  printf 'ERROR: customer1 update returned HTTP %s:\n%s\n' "$status" "$body"
  exit 1
fi
c001_dek_after=$(sed -n 's/.*"dek_hex":"\([0-9a-f]\{64\}\)".*/\1/p' <<<"$body")
if [[ ${#c001_dek_after} -ne 64 || "$c001_dek_after" == "$c001_dek_before" ]]; then
  printf 'ERROR: customer1 update did not expose a fresh 256-bit DEK:\n%s\n' "$body"
  exit 1
fi
printf 'ALLOW customer1 update C001: HTTP 200, version 2 changed the DEK from %s… to %s…\n' "${c001_dek_before:0:12}" "${c001_dek_after:0:12}"

run_access_matrix "REST access matrix after customer update"
if ! grep -q 'msg="record updated"' /tmp/customer-crypto-web.log || ! grep -q 'request_id=req-' /tmp/customer-crypto-web.log; then
  printf 'ERROR: structured REST console logging was not produced\n'
  exit 1
fi
printf '\nIntegration demo passed\n'
