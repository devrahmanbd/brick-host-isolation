#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

test -f contracts/brick-host-isolation-recovery.v1.json
test -f recovery/authority.go
test -f recovery/authority_test.go
test -f cmd/recovery-verify/main.go
test -f docs/PHASE7_RECOVERY.md

gofmt -d recovery cmd | tee /tmp/brick-host-isolation-phase7-gofmt.diff
test ! -s /tmp/brick-host-isolation-phase7-gofmt.diff
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go run ./cmd/lifecycle-verify
go run ./cmd/broker-verify
go run ./cmd/host-verify
go run ./cmd/isolation-verify
go run ./cmd/resource-verify
go run ./cmd/integrity-verify
go run ./cmd/recovery-verify

printf '%s\n' 'Phase 7 recovery validation passed.'
