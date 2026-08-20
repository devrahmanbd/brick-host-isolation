#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

test -f contracts/brick-host-isolation-integrity.v1.json
test -f integrity/authority.go
test -f integrity/authority_test.go
test -f cmd/integrity-verify/main.go
test -f docs/PHASE6_EXECUTABLE_INTEGRITY.md

gofmt -d integrity cmd | tee /tmp/brick-host-isolation-phase6-gofmt.diff
test ! -s /tmp/brick-host-isolation-phase6-gofmt.diff
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go run ./cmd/lifecycle-verify
go run ./cmd/broker-verify
go run ./cmd/host-verify
go run ./cmd/isolation-verify
go run ./cmd/resource-verify
go run ./cmd/integrity-verify

printf '%s\n' 'Phase 6 executable-integrity validation passed.'
