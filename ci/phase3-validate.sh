#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

test -f contracts/brick-host-isolation-host.v1.json
test -f host/host.go
test -f host/host_test.go
test -f cmd/host-verify/main.go
test -f docs/PHASE3_HOST_PREFLIGHT_BASE_ROOT.md

gofmt -d host cmd | tee /tmp/brick-host-isolation-phase3-gofmt.diff
test ! -s /tmp/brick-host-isolation-phase3-gofmt.diff
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go run ./cmd/lifecycle-verify
go run ./cmd/broker-verify
go run ./cmd/host-verify

printf '%s\n' 'Phase 3 host-preflight and base-root validation passed.'
