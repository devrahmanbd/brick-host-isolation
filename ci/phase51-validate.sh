#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

required=(
  contracts/release-evidence-binding.v1.json
  contracts/fixtures/release-evidence-binding.v1.valid.json
  edition/release_evidence_binding.go
  edition/authority.go
  certification/authority.go
  certification/phase51_binding_test.go
  cmd/edition-verify/main.go
  cmd/certification-verify/main.go
  docs/PHASE51_SR001_RELEASE_EVIDENCE_BINDING.md
)
for path in "${required[@]}"; do
  test -f "$path"
done

test -z "$(gofmt -l edition certification cmd/edition-verify cmd/certification-verify)"
go test -race -count=1 ./edition ./certification
go vet ./edition ./certification ./cmd/edition-verify ./cmd/certification-verify
go run ./cmd/edition-verify
go run ./cmd/certification-verify

: "${BRICK_CORE_DIR:?BRICK_CORE_DIR must identify the independently checked-out Core release}"
test -d "$BRICK_CORE_DIR"
test -f "$BRICK_CORE_DIR/contracts/release-evidence-binding.v1.json"
test -f "$BRICK_CORE_DIR/contracts/fixtures/release-evidence-binding.v1.valid.json"
cmp -s contracts/release-evidence-binding.v1.json "$BRICK_CORE_DIR/contracts/release-evidence-binding.v1.json"

(
  export BRICK_RELEASE_EVIDENCE_BINDING_FIXTURE="$BRICK_CORE_DIR/contracts/fixtures/release-evidence-binding.v1.valid.json"
  go run ./cmd/edition-verify
)
(
  export BRICK_RELEASE_EVIDENCE_BINDING_FIXTURE="$PWD/contracts/fixtures/release-evidence-binding.v1.valid.json"
  cd "$BRICK_CORE_DIR/core"
  go run ./cmd/release-evidence-binding-verify
)
(cd "$BRICK_CORE_DIR/core" && go test -race -count=1 ./app/service)
