SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:
.DEFAULT_GOAL := help

GO ?= go
CURL ?= curl
NODE ?= node

DB ?= demo.db
IDENTITIES ?= identities
GRPC_ADDR ?= 127.0.0.1:50051
WEB_ADDR ?= 127.0.0.1:8080
REST_URL ?= http://$(WEB_ADDR)

IDENTITY ?= customer1
IDENTITY_FILE ?= $(IDENTITIES)/$(IDENTITY).json
ROTATION_IDENTITY ?= $(IDENTITIES)/rotation.json
OBJECT ?= C001
VERSION ?= 0
FIELD ?= city
VALUE ?= Gothenburg
TARGET ?= backoffice1

.PHONY: help deps test vet check check-scripts check-js integration demo \
	reset bootstrap server seed web client update revoke jobs rotate \
	rest-health rest-config rest-read rest-update

help:
	@printf '%-18s %s\n' \
		'make demo' 'Start a fresh temporary gRPC + REST/web demo; Ctrl+C stops it' \
		'make integration' 'Run the complete REST, ACL, update, logging, and gRPC integration test' \
		'make deps' 'Download and tidy Go modules' \
		'make test' 'Run all Go tests' \
		'make vet' 'Run go vet for all packages' \
		'make check' 'Run Go tests, go vet, and shell syntax checks' \
		'make check-js' 'Check browser JavaScript syntax with Node.js' \
		'make reset' 'Remove the configured demo database and identity directory' \
		'make bootstrap' 'Provision the configured database and identity files' \
		'make server' 'Start the gRPC server in the foreground' \
		'make seed' 'Seed C001, C002, and C003 through the rotation identity' \
		'make web' 'Start the REST API and web client in the foreground' \
		'make client' 'Read a record with IDENTITY, OBJECT, and VERSION' \
		'make update' 'Update FIELD=VALUE on OBJECT as IDENTITY' \
		'make revoke' 'Revoke TARGET through the rotation identity' \
		'make jobs' 'List pending rotation jobs' \
		'make rotate' 'Process pending rotation jobs' \
		'make rest-health' 'Call the REST health endpoint' \
		'make rest-config' 'Show identities and expected ACL without credentials' \
		'make rest-read' 'Read OBJECT over REST as IDENTITY' \
		'make rest-update' 'Update FIELD=VALUE on OBJECT over REST as IDENTITY'
	@printf '\nCommon overrides:\n'
	@printf '  DB=%s IDENTITIES=%s GRPC_ADDR=%s WEB_ADDR=%s\n' "$(DB)" "$(IDENTITIES)" "$(GRPC_ADDR)" "$(WEB_ADDR)"
	@printf '  IDENTITY=%s OBJECT=%s VERSION=%s FIELD=%s VALUE=%s TARGET=%s\n' "$(IDENTITY)" "$(OBJECT)" "$(VERSION)" "$(FIELD)" "$(VALUE)" "$(TARGET)"

deps:
	$(GO) mod tidy

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

check-scripts:
	bash -n scripts/integration.sh

check-js:
	$(NODE) --check webapp/static/app.js

check: test vet check-scripts

integration:
	./scripts/integration.sh

reset:
	db_path="$(abspath $(DB))"
	identities_path="$(abspath $(IDENTITIES))"
	workspace="$(CURDIR)"
	case "$$db_path" in "$$workspace"/*) ;; *) printf 'Refusing to remove DB outside %s: %s\n' "$$workspace" "$$db_path"; exit 1 ;; esac
	case "$$identities_path" in "$$workspace"/*) ;; *) printf 'Refusing to remove identities outside %s: %s\n' "$$workspace" "$$identities_path"; exit 1 ;; esac
	if [[ "$$db_path" == "$$workspace" || "$$identities_path" == "$$workspace" ]]; then
		printf 'Refusing to remove the workspace root\n'
		exit 1
	fi
	rm -f -- "$$db_path"
	rm -rf -- "$$identities_path"
	printf 'Removed %s and %s\n' "$$db_path" "$$identities_path"

bootstrap:
	$(GO) run ./cmd/bootstrap -db "$(DB)" -identities "$(IDENTITIES)"

server:
	$(GO) run ./cmd/server -db "$(DB)" -listen "$(GRPC_ADDR)"

seed:
	$(GO) run ./cmd/rotation -identity "$(ROTATION_IDENTITY)" -server "$(GRPC_ADDR)" -action seed

web:
	$(GO) run ./cmd/web -identities "$(IDENTITIES)" -grpc "$(GRPC_ADDR)" -listen "$(WEB_ADDR)"

client:
	$(GO) run ./cmd/client -identity "$(IDENTITY_FILE)" -server "$(GRPC_ADDR)" -object "$(OBJECT)" -version "$(VERSION)"

update:
	$(GO) run ./cmd/client -identity "$(IDENTITY_FILE)" -server "$(GRPC_ADDR)" -object "$(OBJECT)" -set "$(FIELD)=$(VALUE)"

revoke:
	$(GO) run ./cmd/rotation -identity "$(ROTATION_IDENTITY)" -server "$(GRPC_ADDR)" -action revoke -target "$(TARGET)"

jobs:
	$(GO) run ./cmd/rotation -identity "$(ROTATION_IDENTITY)" -server "$(GRPC_ADDR)" -action jobs

rotate:
	$(GO) run ./cmd/rotation -identity "$(ROTATION_IDENTITY)" -server "$(GRPC_ADDR)" -action rotate

rest-health:
	$(CURL) -fsS "$(REST_URL)/api/v1/health"
	printf '\n'

rest-config:
	$(CURL) -fsS "$(REST_URL)/api/v1/config"
	printf '\n'

rest-read:
	$(CURL) -sS -H 'Accept: application/json' -H "X-Demo-Identity: $(IDENTITY)" "$(REST_URL)/api/v1/records/$(OBJECT)"
	printf '\n'

rest-update:
	payload=$$(printf '{"changes":{"%s":"%s"}}' "$(FIELD)" "$(VALUE)")
	$(CURL) -sS -X PATCH -H 'Accept: application/json' -H 'Content-Type: application/json' -H "X-Demo-Identity: $(IDENTITY)" --data "$$payload" "$(REST_URL)/api/v1/records/$(OBJECT)"
	printf '\n'

demo:
	demo_dir="$$(mktemp -d /tmp/customer-crypto-demo.XXXXXX)"
	server_pid=""
	cleanup() {
		if [[ -n "$$server_pid" ]]; then
			kill "$$server_pid" 2>/dev/null || true
			wait "$$server_pid" 2>/dev/null || true
		fi
		rm -rf -- "$$demo_dir"
	}
	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	printf 'Preparing temporary demo in %s\n' "$$demo_dir"
	$(GO) build -o "$$demo_dir/bootstrap" ./cmd/bootstrap
	$(GO) build -o "$$demo_dir/server" ./cmd/server
	$(GO) build -o "$$demo_dir/rotation" ./cmd/rotation
	$(GO) build -o "$$demo_dir/web" ./cmd/web
	"$$demo_dir/bootstrap" -db "$$demo_dir/demo.db" -identities "$$demo_dir/identities"
	"$$demo_dir/server" -db "$$demo_dir/demo.db" -listen "$(GRPC_ADDR)" &
	server_pid=$$!
	sleep 1
	if ! kill -0 "$$server_pid" 2>/dev/null; then
		printf 'gRPC server failed to start on %s\n' "$(GRPC_ADDR)"
		exit 1
	fi
	"$$demo_dir/rotation" -identity "$$demo_dir/identities/rotation.json" -server "$(GRPC_ADDR)" -action seed
	printf '\nWeb demo ready at http://%s\nPress Ctrl+C to stop and remove temporary data.\n\n' "$(WEB_ADDR)"
	"$$demo_dir/web" -identities "$$demo_dir/identities" -grpc "$(GRPC_ADDR)" -listen "$(WEB_ADDR)"
