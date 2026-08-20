#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

required=(
  contracts/brick-host-isolation-certification.v1.json
  certification/authority.go
  certification/authority_test.go
  cmd/certification-verify/main.go
  docs/PHASE9_CERTIFICATION_GUARDED_RELEASE.md
  release/phase9-source.sbom.template.cdx.json
  release/phase9-artifact-manifest.template.json
  release/phase9-security-review.template.json
)
for path in "${required[@]}"; do test -f "$path"; done

test -z "$(gofmt -l certification cmd/certification-verify)"
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go run ./cmd/lifecycle-verify/
go run ./cmd/broker-verify/
go run ./cmd/host-verify/
go run ./cmd/isolation-verify/
go run ./cmd/resource-verify/
go run ./cmd/integrity-verify/
go run ./cmd/recovery-verify/
go run ./cmd/edition-verify/
go run ./cmd/certification-verify/
