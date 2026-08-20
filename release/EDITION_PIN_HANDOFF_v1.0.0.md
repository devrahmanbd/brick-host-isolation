# Shared and Dedicated Edition Pin Handoff — v1.0.0

## Current status

No Shared or Dedicated release pin exists for candidate `v1.0.0` at `b2ff94d6f8496bd9f14fe55cff651422b953d31c`, and no deployment-change approval exists. This is intentional: there is no valid guarded-release certificate, no pinned certificate verification key, and no complete protected evidence bundle.

> A source commit, a preliminary SBOM, a pre-signing manifest, a preliminary benchmark, fixture-verifier success, or a draft release document is never a pin authorization. The only acceptable trigger is an independently verified, unexpired Phase 9 guarded-release certificate whose digests match the retained protected inputs exactly.

## Required verification before pinning

| Verification class | Required assertion | Failure result |
|---|---|---|
| Certificate identity | Certificate release ID is `v1.0.0`; source commit is exactly `b2ff94d6f8496bd9f14fe55cff651422b953d31c`. | Deny both pins. |
| Certificate signature and time | `certification.VerifyCertificate` succeeds against the pinned protected certificate public key and current trusted time precedes `expiresAt`. | Deny both pins. |
| Artifact and SBOM | Certificate manifest and SBOM digests equal the independently verified protected artifact-manifest record and actual SBOM. | Deny both pins. |
| Benchmark and review | Certificate benchmark/review digests equal valid protected signed records; review is independently approved, unexpired, and in scope. | Deny both pins. |
| Edition staging | Certificate has one digest for each edition; each matches the valid current signed real-host Phase 8 evidence for the matching edition/profile. | Deny the affected edition; do not infer equivalence from the other edition. |
| Core policy | Certificate includes exactly the three current Shared or Dedicated Core gate digests matching the respective edition’s admission, certification, and GA records. | Deny the affected edition. |
| Protected audit and retention | Protected store has the complete input bundle, certificate, independent verifier receipt, broker correlation, replay-ID claim, and audit correlation. | Deny both pins. |

## Immutable pin record requirements

Create two **separate** records only after all checks pass: one with `edition=shared`, one with `edition=dedicated`. Each record must be signed or otherwise immutably approved by that edition’s protected deployment-change authority and include these values copied from independently verified protected records:

| Field | Required value |
|---|---|
| Edition and target profile | Exact edition plus matching immutable Shared or Dedicated profile ID/digest. |
| Release ID and source commit | `v1.0.0` and `b2ff94d6f8496bd9f14fe55cff651422b953d31c`. |
| Certificate identity | Certificate ID, certificate SHA-256 digest, issuance/expiry, signer key ID, and verifier receipt digest. |
| Artifact chain | Artifact-manifest digest, SBOM digest, source-archive digest, and protected evidence location/reference. |
| Quality and review | Benchmark-evidence digest, security-review digest, review expiry, and protected evidence locations/references. |
| Edition-specific evidence | Only that edition’s staging-evidence digest, evidence ID, cage/profile binding digest, signer key ID, and verifier receipt. |
| Core gates | Only that edition’s admission, certification, and GA record IDs/digests/expiry/key IDs. |
| Approval and audit | Change-request ID, independent approver identities, approval timestamp, deployment window, rollback target, broker/audit correlation, and protected retention references. |

The records must never include private keys, raw tenant data, unredacted host paths, broker credentials, or any secret from the evidence store. Pin data may reference protected evidence by immutable ID and digest rather than copying sensitive contents into an edition repository.

## Deployment-change approval sequence

1. A release operator prepares a candidate-specific change request referencing the immutable pin record and a rollback target. The operator cannot approve their own change.
2. An independent release approver verifies the certificate and required evidence directly from protected storage, not from repository documentation or operator-provided digest text.
3. The edition deployment authority writes an immutable signed/approved change record containing the complete field set above. The audit sink must accept the authorization event before the approval result is returned.
4. Deploy only the exact pinned immutable artifact. Recompute its digest before activation and stop if it differs from the pin record.
5. After activation, record an attestation of the deployed digest, instance/host scope, change correlation, monitoring baseline, and rollback readiness. Any certificate expiry, revocation, audit failure, or digest mismatch halts rollout and invokes the Phase 7 recovery path.

## Current blockers

The candidate lacks every protected prerequisite: no authenticated production broker, no pinned certificate public key, no guarded-release certificate, no signed artifact manifest, no signed benchmark record, no approved review, no independent real-host staging evidence, no six Core gates, and no protected retention/audit services. The preliminary review is explicitly rejected and identifies SR-001 and SR-004 as high-severity blockers.

No deployment-change approval can be requested until SR-001 is remediated, the real-host matrix is complete, protected signing/review/Core gates are in place, and Phase 9 returns a verifiable certificate.
