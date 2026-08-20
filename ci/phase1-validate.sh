#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

test -f contracts/brick-host-isolation.v1.json
test -f lifecycle/authority.go
test -f lifecycle/authority_test.go
test -f cmd/lifecycle-verify/main.go
test -f docs/PHASE1_LIFECYCLE_ATTESTATION.md

gofmt -d lifecycle cmd | tee /tmp/brick-host-isolation-gofmt.diff
test ! -s /tmp/brick-host-isolation-gofmt.diff
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go run ./cmd/lifecycle-verify

printf '%s\n' 'Phase 1 lifecycle and attestation validation passed.'
