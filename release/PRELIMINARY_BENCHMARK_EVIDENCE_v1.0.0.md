# Preliminary Benchmark Evidence — v1.0.0

## Status and boundary

This transcript records **unsigned preliminary certification benchmark evidence** for `v1.0.0` at `b2ff94d6f8496bd9f14fe55cff651422b953d31c`. It is bound to the selected candidate, raw benchmark output, and captured environment through SHA-256. It is not a Phase 9 signed benchmark-evidence record, a guarded-release certificate, a performance SLO, or authorization to pin or deploy an edition.

The raw output, environment record, and pre-signing handoff remain outside source control pending protected-evidence-store transfer. The protected benchmark-evidence signer must independently verify those exact bytes before signing.

## Measurement protocol and environment

| Field | Recorded value |
|---|---|
| Candidate release | `v1.0.0` |
| Source commit | `b2ff94d6f8496bd9f14fe55cff651422b953d31c` |
| Source tree | `1b8dc89b5cd6b3197065d5894f0a893830b32447` |
| Benchmark target | `BenchmarkCertifyCompleteEvidence` |
| Benchmark command | `GOMAXPROCS=1 go test -run '^$' -bench '^BenchmarkCertifyCompleteEvidence$' -benchtime=3s -count=5 -cpu=1 -benchmem ./certification` |
| Go runtime | `go1.22.2 linux/amd64` |
| OS/kernel | `Linux 6.18.38+ x86_64 GNU/Linux` |
| CPU model / logical CPUs | `Intel(R) Xeon(R) Processor @ 2.10GHz` / `6` |
| Environment record SHA-256 | `f73cda319c3553e662c1809cbcf89c4e80aa526249ee03cc095e376ac5dad964` |
| Raw output SHA-256 | `20be6855ea7cb1eca68cec4d299e90089e3de22e954ecfc9aa0481b8e7af36fa` |

The benchmark fixture performs complete in-memory Phase 9 certification over valid signed evidence. It therefore measures the authority’s local evidence-verification and certificate-creation path, not broker transport, mTLS, protected audit persistence, KMS/HSM latency, staging-host execution, or customer workload performance.

## Repeated measurement results

| Repetition | Iterations | Nanoseconds/op | Bytes/op | Allocations/op |
|---:|---:|---:|---:|---:|
| 1 | 4,335 | 809,303 | 35,317 | 208 |
| 2 | 4,573 | 786,520 | 35,314 | 208 |
| 3 | 4,519 | 805,831 | 35,314 | 208 |
| 4 | 4,545 | 797,247 | 35,314 | 208 |
| 5 | 4,598 | 827,396 | 35,313 | 208 |
| **Mean** | — | **805,259.4** | **35,314.4** | **208** |

The minimum was `786,520 ns/op`, the maximum was `827,396 ns/op`, and the population standard deviation was `13,579.91 ns/op` (coefficient of variation `1.6864%`). This local variation is recorded for reproducibility; it is not an acceptance threshold or a production capacity claim.

## Evidence handoff and signing hold

The unsigned, validated pre-signing evidence payload has SHA-256 **`6fc39c4b5f117fd8f1c5772ae8b2370f9ae0293ca562f6dcd176ac28c571dd88`**. It has the exact Phase 9 benchmark record fields, candidate release and commit, environment digest, and five strictly ordered repetition results, but is explicitly marked `PENDING_PROTECTED_BENCHMARK_SIGNER` with no signature.

> **Required next action:** Transfer the exact raw output, environment record, and pre-signing payload to the protected evidence store. The independent benchmark-evidence signer must verify the candidate and environment bindings; replace `pending-protected-ed25519` with `ed25519`; sign the canonical `brick.host-isolation.benchmark-evidence.v1` payload; and retain the valid signed record with the signer key identifier and protected audit correlation.
