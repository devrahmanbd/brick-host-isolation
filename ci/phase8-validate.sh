#!/usr/bin/env bash
set -euo pipefail
repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
test -f contracts/brick-host-isolation-edition.v1.json
test -f edition/authority.go
test -f edition/authority_test.go
test -f cmd/edition-verify/main.go
test -f docs/PHASE8_EDITION_STAGING.md
gofmt -d edition cmd | tee /tmp/brick-host-isolation-phase8-gofmt.diff
test ! -s /tmp/brick-host-isolation-phase8-gofmt.diff
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
for verifier in lifecycle broker host isolation resource integrity recovery edition; do go run "./cmd/${verifier}-verify"; done
printf '%s\n' 'Phase 8 edition and staging validation passed.'
