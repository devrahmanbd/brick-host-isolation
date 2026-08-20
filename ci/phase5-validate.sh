#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

test -f contracts/brick-host-isolation-resource.v1.json
test -f resource/authority.go
test -f resource/authority_test.go
test -f cmd/resource-verify/main.go
test -f docs/PHASE5_RESOURCE_EGRESS.md

gofmt -d resource cmd | tee /tmp/brick-host-isolation-phase5-gofmt.diff
test ! -s /tmp/brick-host-isolation-phase5-gofmt.diff
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go run ./cmd/lifecycle-verify
go run ./cmd/broker-verify
go run ./cmd/host-verify
go run ./cmd/isolation-verify
go run ./cmd/resource-verify

printf '%s\n' 'Phase 5 resource and egress-policy validation passed.'
