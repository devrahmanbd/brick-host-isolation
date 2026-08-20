# Preliminary Security Review — v1.0.0

## Review status

| Field | Recorded value |
|---|---|
| Candidate | `v1.0.0` |
| Immutable source commit | `b2ff94d6f8496bd9f14fe55cff651422b953d31c` |
| Review scope | `artifact-manifest`, `engine`, `staging-evidence` |
| Assessment method | Static control-flow review, trust-binding review, focused race-enabled tests, static analysis, and complete Phase 9 gate. |
| Preliminary outcome | **Rejected — not eligible for an approved security-review signature.** |
| Findings digest | `250f755d3df59d3f53e73e39558e4e058ff04309e6f5cd248c25ded55a71625b` (`release/security-review-v1.0.0.findings.canonical.json`) |
| Review-signature status | No signature. This assessment is not an independent, separately controlled sign-off. |

This review was performed in the development workspace by the implementation agent and is necessarily **not independent** from the implementation. It must not be substituted for the required protected reviewer process. The Phase 9 security-review authority would correctly reject this record because its outcome is not `approved` and it has no valid Ed25519 signature.

## Evidence examined

The review examined the selected candidate’s Phase 9 certification authority, Phase 8 edition/staging authority, deterministic adversarial tests, contract, and the recorded preliminary SBOM/manifest/benchmark material. The following validation commands completed successfully against the detached candidate worktree:

```text
go test -race -count=1 -v ./certification ./edition
go vet ./...
bash ci/phase9-validate.sh
```

The focused authority suites passed all certification and edition tests. The complete gate passed all package tests, all race checks, static analysis, and all nine standalone verifiers. These results increase confidence in implemented branches but do not prove real-host staging, protected signing, durable audit retention, or an independent review.

## Findings

| ID | Severity | Scope | Finding | Required disposition |
|---|---|---|---|---|
| SR-001 | **High** | Engine / staging evidence | Phase 9 accepts a fresh valid Shared and Dedicated Phase 8 evidence record without cryptographically binding either record to the Phase 9 `sourceCommit`, artifact manifest digest, or SBOM digest. A separately valid, recent staging record may therefore be replayed across candidate commits if its Phase 4–6 binding digest remains syntactically valid. | Do not approve. Extend the signed Phase 8 evidence or its Phase 9 verification context with immutable candidate identity, reject mismatch, add adversarial tests, and regenerate real-host evidence after remediation. |
| SR-002 | **Medium** | Engine / certification replay | `Authority.Certify` checks format, limiter, and evidence but retains no certificate-ID replay state. It relies on the external broker/replay ledger being correctly deployed. A direct or incorrectly integrated authority caller could request more than one certificate with the same caller-provided ID while evidence is valid. | Require the Phase 2 replay-resistant broker as the only production entry point; bind issuance to a durable idempotency/replay record and add integration coverage that direct authority exposure is impossible. |
| SR-003 | **Medium** | Artifact manifest | The manifest authority validates a signed SBOM digest but does not parse/reconcile the SBOM, source archive, and artifact bytes. That is an appropriate separation for a signing authority, but a protected signer could sign a syntactically valid manifest whose referenced bytes are absent or whose SBOM metadata is inconsistent unless the release ceremony independently checks it. | Keep the certificate denied until the artifact signer/evidence store performs byte-level retrieval, SHA-256 recomputation, SBOM candidate identity validation, and protected retention. Add a signed verification attestation or make the verifier result part of the manifest evidence. |
| SR-004 | **High** | Staging evidence | There are no real isolated Shared or Dedicated host records for this candidate. Fixture evidence exercises only protocol behavior and cannot demonstrate namespace, filesystem, network, cgroup, audit-store, recovery, or cross-tenant controls on an operating host. | Do not approve. Attach independently controlled disposable staging hosts, run all fifteen scenarios for both profiles, retain raw evidence, and obtain two signed records after SR-001 remediation. |

## Positive control observations

The artifact-manifest verifier rejects empty lists, non-relative/ambiguous paths, non-increasing paths, invalid SHA-256 forms, non-positive sizes, stale timestamps, and invalid signatures. The certification authority requires the exact release and source commit to match across manifest, benchmark, review, and Core gates; it also requires both edition evidence records and exactly six unique Core records.

The engine is largely fail-closed: invalid trust configuration is unavailable; cancellation precedes rate-limit use; rate-limit refusal is denied and audited; mandatory-evidence validation precedes certificate output; denial audit failure masks the denial; and authorization audit failure prevents the signed certificate from being returned. Signature verification uses role-specific Ed25519 public keys and canonical payloads with the signature field cleared.

The Phase 8 evidence format requires exactly fifteen successful observations in a fixed order, validates profile/edition pairing, verifies the Ed25519 signature, and rejects malformed observation digests. The staging authority stops on the first failed scenario and does not emit evidence before the authorization audit accepts the event.

## Required remediation and review exit

The next security work must remediate SR-001 before new staging runs because existing evidence cannot demonstrate candidate-specific execution. The production integration must remediate or explicitly enforce SR-002 with the Phase 2 broker and durable replay ledger. SR-003 must be addressed during protected signer/evidence-store operation, and SR-004 requires real independent host evidence.

After remediation, an independently controlled reviewer must repeat this review using the repaired exact candidate, raw protected evidence, trust-bundle/key-custody records, actual signed artifact manifest, actual signed benchmark record, both signed staging records, and six signed Core gates. Only then may that reviewer create an `approved` `brick.host-isolation.security-review.v1` record with a short expiry and a non-reused review ID.

> **Final preliminary assessment:** The candidate is **not approved for guarded-release certification**. This is a deliberate fail-closed review outcome, not a production-release decision.
