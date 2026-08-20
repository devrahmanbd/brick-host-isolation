#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

test -f contracts/brick-host-isolation-broker.v1.json
test -f broker/broker.go
test -f broker/ledger.go
test -f broker/broker_test.go
test -f cmd/broker-verify/main.go
test -f docs/PHASE2_ROOT_BROKER.md

gofmt -d broker cmd | tee /tmp/brick-host-isolation-phase2-gofmt.diff
test ! -s /tmp/brick-host-isolation-phase2-gofmt.diff
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go run ./cmd/lifecycle-verify
go run ./cmd/broker-verify

printf '%s\n' 'Phase 2 root-broker validation passed.'
