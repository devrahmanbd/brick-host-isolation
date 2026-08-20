# Guarded Release Submission Handoff — v1.0.0

## Current decision

Do **not** submit candidate `v1.0.0` at `b2ff94d6f8496bd9f14fe55cff651422b953d31c` to the Phase 9 certification authority. The current environment has no attached production broker, protected trust bundle, pinned certificate public key, protected audit sink, or evidence-retention store. More importantly, the mandatory evidence bundle is incomplete and includes no valid approved security review.

Submitting placeholders, unsigned pre-signing payloads, fixture keys, local audit sinks, or an intentionally rejected review would be an authorization-bypass attempt. A correctly configured Phase 9 authority must deny this candidate before issuing a certificate.

| Required submission input | Required state | Current state | Submission eligibility |
|---|---|---|---|
| Authenticated broker | Root-owned production broker with socket/TLS/peer UID/SPIFFE policy, rate limit, durable replay ledger, and audit-before-response path. | Not attached or configured. | Blocked |
| Artifact manifest | Valid protected-signer Ed25519 `brick.host-isolation.artifact-manifest.v1` record; exact candidate bytes and SBOM digest. | Only unsigned pre-signing payload exists. | Blocked |
| Benchmark evidence | Valid protected-signer Ed25519 `brick.host-isolation.benchmark-evidence.v1` record. | Only unsigned pre-signing payload exists. | Blocked |
| Security review | Independent, signed, unexpired `approved` review covering all three mandatory scopes. | Preliminary review is unsigned and `rejected`; SR-001 through SR-004 remain. | Blocked |
| Shared staging evidence | Valid signed Phase 8 record from an independent real isolated Shared host. | No real-host evidence or signer exists. | Blocked |
| Dedicated staging evidence | Valid signed Phase 8 record from an independent real isolated Dedicated host. | No real-host evidence or signer exists. | Blocked |
| Core gates | Six current approved, signed and unexpired Core records. | No generic Core cross-repository authority; no protected Core signer; prerequisite evidence is incomplete. | Blocked |
| Certificate verification | Pinned certificate public key from the protected trust bundle. | Not provisioned in this environment. | Blocked |
| Retention and audit | Protected immutable input/certificate retention and durable audit correlation. | Not provisioned in this environment. | Blocked |

## Controlled submission sequence

Execute these steps only in the protected release environment after every row above is resolved. Do not use this source repository as the private-key, evidence, or audit store.

1. Load the current public trust bundle and verify that every signing key ID and public key is distinct, trusted, unrevoked, and authorized for exactly its evidence role. Confirm the certificate verifier uses the pinned certificate public key from the same trust bundle.
2. Verify all eight evidence classes **before** contacting the broker: artifact manifest, benchmark evidence, security review, Shared evidence, Dedicated evidence, Shared admission/certification/GA, and Dedicated admission/certification/GA. For every record verify the schema, exact release ID, exact full source commit, expiry, canonical Ed25519 signature, signer role, and required semantic bindings.
3. Ensure the production broker is owned by the configured privileged service account; verify Unix socket owner/mode, TLS 1.3/mTLS material, exact SPIFFE caller identity, peer UID allowlist, rate-limit behavior, durable replay-ledger write/read, host preflight, and a live protected audit append/read-back. Use a fresh certificate ID after confirming no existing ledger claim.
4. Submit one authenticated certification request through the broker. Record a protected request digest, broker correlation/replay ID, policy digest, audit-event correlation, and a durable immutable receipt. Do not record private keys, tenant content, raw host paths, or secret material in source control.
5. Verify the returned certificate independently with `certification.VerifyCertificate` using the pinned certificate public key. Require exact candidate release/commit linkage, non-expired issuance window, valid canonical Ed25519 certificate signature, and expected evidence digests.
6. Retain the exact input records, raw protected evidence references, request digest, certificate, independent verifier result, audit correlation, signer/key IDs, and retention location under the release-retention policy. Only after independent verification may an edition evaluate an immutable release pin.

## Certificate acceptance checklist

| Check | Required assertion |
|---|---|
| Identity | Certificate release ID is `v1.0.0` and source commit is `b2ff94d6f8496bd9f14fe55cff651422b953d31c`. |
| Time | `issuedAt` is current, `expiresAt` is within configured certificate TTL, and verification time precedes expiry. |
| Evidence | Manifest, SBOM, benchmark, review, both staging evidence, and all six Core-gate digests equal independently verified submitted inputs. |
| Signature | Algorithm is literal `ed25519`; canonical certificate payload verifies under the pinned protected certificate public key. |
| Audit | Protected audit store contains exactly one issuance correlation matching the request/certificate; replay ledger contains the claimed certificate ID. |
| Retention | Protected immutable storage contains inputs, certificate, verifier receipt, and audit correlation before any edition pin proceeds. |

> **Current status:** zero of the conditions above is satisfied sufficiently for issuance. The next engineering action is remediation of SR-001 and the required protected release/staging/Core infrastructure; it is not a broker submission retry.
