#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

test -f contracts/brick-host-isolation-isolation.v1.json
test -f isolation/authority.go
test -f isolation/authority_test.go
test -f cmd/isolation-verify/main.go
test -f docs/PHASE4_ISOLATION_PLAN.md

gofmt -d isolation cmd | tee /tmp/brick-host-isolation-phase4-gofmt.diff
test ! -s /tmp/brick-host-isolation-phase4-gofmt.diff
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go run ./cmd/lifecycle-verify
go run ./cmd/broker-verify
go run ./cmd/host-verify
go run ./cmd/isolation-verify

printf '%s\n' 'Phase 4 isolation-plan validation passed.'
