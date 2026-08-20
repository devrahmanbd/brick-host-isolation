# Phase 9 — Certification and Guarded Release

## Purpose and boundary

Phase 9 is the **release-admission authority** for Brick Host Isolation. It produces a short-lived, Ed25519-signed certificate only after independently signed evidence is coherent for one immutable semantic release and source commit. It is a planning and certification boundary. It does not execute a cage, run a privileged syscall, tag a Git revision, publish an artifact, or grant a workload access.

The authority preserves the permanent product topology. `core` remains upstream-only and emits its own signed admission, certification, and GA decisions. `shared` and `dedicated` remain consumers; they do not fork the engine. Both editions must show their own valid Phase 8 staging evidence and all three valid Core gates before a release certificate can be issued.

| Required signed record | Signing trust root | Mandatory checks |
|---|---|---|
| Artifact manifest and SBOM digest | Release artifact signer | Semantic release ID, immutable source commit, ordered safe relative paths, SHA-256 digests, positive sizes, fresh issuance. |
| Benchmark evidence | Performance evidence signer | Same release and commit, bounded freshness, non-empty deterministic benchmark results, declared environment digest. |
| Security review | Independent security-review signer | Approved outcome, required review scope, bounded review lifetime, reviewer SPIFFE identity, findings digest. |
| Shared and Dedicated staging evidence | Protected Phase 8 evidence signer | Valid Phase 8 signature, full mandatory scenario matrix, edition/profile coherence, bounded freshness. |
| Core policy gates | Core admission signer | Both editions each require **admission**, **certification**, and **GA** gates; all must be approved, unexpired, and bound to the exact release and commit. |

## Fail-closed behavior

Missing dependencies, cancellation, malformed or replayed identifiers, caller identity failure, rate-limit rejection, an audit failure, stale evidence, expired review, missing edition evidence, signature failure, source/release mismatch, duplicate Core gate, missing GA gate, unsafe artifact path, or certificate tampering causes denial. The authority records its authorization outcome in the protected audit sink before returning a result. It never reduces the requirement to a single digest supplied by a caller.

The certificate contains only safe linkage information: release ID, source commit, artifact-manifest/SBOM/benchmark/review digests, staging-evidence digests, Core-gate digests, issuance/expiry, and its signature. It contains no workload secret, host path, signing private key, or panel/control-plane material.

## Release ceremony

The following process must occur in a protected release environment; the source templates under `release/` are **not evidence** and must never be submitted as though they were signed release records.

1. Build the candidate from a clean, immutable source commit and write the actual CycloneDX SBOM from the exact build inputs. Hash the SBOM with SHA-256.
2. Produce an ordered artifact manifest with relative artifact paths only. Sign it with the dedicated artifact signing key held outside the build workspace.
3. Run and retain reproducible benchmark evidence. Bind it to the commit and independently sign it with the benchmark evidence key.
4. Execute the Phase 8 matrix on independent isolated Shared and Dedicated staging hosts, retain the protected full evidence, and use only valid signed results for this candidate.
5. Obtain an independent approved review whose scope exactly covers `artifact-manifest`, `engine`, and `staging-evidence`. Sign it with the review key and set a short review expiry.
6. Require Core to issue current signed **admission**, **certification**, and **GA** gate records for Shared and Dedicated. Any denial, expiry, or different commit invalidates the candidate.
7. Submit the complete records to the Phase 9 authority through its authenticated, rate-limited production broker. Retain the returned certificate, protected audit record, and all input evidence together.
8. Only after the certificate verifies under the pinned certificate public key may Shared or Dedicated pin the immutable signed release. Pin the release ID, exact source commit, certificate digest, and relevant evidence digests together.

## Key management and retention

Each evidence role must use a distinct Ed25519 key. The artifact, benchmark, review, Phase 8 staging, Core-gate, and certificate private keys must remain in separately controlled protected stores. Do not use development fixture keys, put private keys in source control, or reuse an edition caller key for release certification. Rotate keys through a dual-trust migration with an independently reviewed revocation record; deny issuance if the current configured trust bundle is incomplete.

Retain the certificate, manifest, SBOM, benchmark record, review record, both staging records, all six Core records, and protected audit correlation for the full artifact-retention period. If a signer is compromised, a review expires, or any evidence is found incorrect, revoke the affected release externally, halt new pins, and route affected cages through the Phase 7 kill-first recovery process rather than attempting an in-place trust override.

## Validation

Run the standalone proof from the repository root:

```bash
go run ./cmd/certification-verify/
bash ci/phase9-validate.sh
```

The verifier uses ephemeral fixture keys and proves only the contract and authority mechanics. It does not create a production certificate and cannot replace the protected release ceremony above.
