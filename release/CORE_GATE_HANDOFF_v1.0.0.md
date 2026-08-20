# Core Gate Handoff — v1.0.0

## Result

The requested six current **approved** Core gate records cannot be issued for Brick Host Isolation candidate `v1.0.0` at `b2ff94d6f8496bd9f14fe55cff651422b953d31c`. No record was created, signed, or represented as Core evidence.

This is a correct fail-closed result. The existing Core authorities govern Core and Shared beta workflows, not a generic cross-repository host-isolation candidate. In addition, the required evidence is incomplete and the preliminary security review outcome is rejected.

| Requested decision | Existing Core capability | Current result |
|---|---|---|
| Shared admission | Phase 48 authority admits an individual **Shared beta tenant** under a Shared-only feature policy. | Cannot issue a host-isolation release admission record. |
| Dedicated admission | No Dedicated admission authority is present; the Shared policy prohibits `dedicated_control_plane`. | Cannot issue. |
| Shared certification | Phase 49 certifies one Core release commit against a Core evidence policy and trusted Core signers. | Cannot issue for the host-isolation repository candidate. |
| Dedicated certification | No Dedicated-specific certification authority is present. | Cannot issue. |
| Shared GA | Phase 50 authorizes bounded growth of a Shared closed-beta cohort. | Cannot issue a host-isolation release GA record. |
| Dedicated GA | No Dedicated GA authority is present. | Cannot issue. |

## Verified scope and trust blockers

Core Phase 12 `brick.shared-release-decision.v1` permits only the literal `shared` edition and binds a Core commit. Phase 48 accepts only `TargetEdition == "shared"` and explicitly prohibits Dedicated control-plane capabilities. Phase 49 production certification requires a candidate-bound Core policy, protected evidence/reviewer key maps, signed artifacts, SBOM, a regression matrix, a rollback rehearsal, and zero unaccepted open P1 findings. The committed Core policy currently references Core commit `d4e981c...`, placeholder evidence digests, and Core phase evidence; it is not the selected host-isolation source commit.

Phase 50 is a Shared closed-beta cohort-expansion authority, not a generic edition release signer. It can consume a `host_isolation` evidence class as one input to Shared cohort expansion, but it cannot create a Dedicated decision or substitute for a host-isolation guarded-release policy.

No separately controlled Core signing environment, current trust bundle, protected audit store, or Core private signer was attached to this session. Producing Ed25519 fixture signatures would therefore be indistinguishable from fabricated evidence and is prohibited.

| Independent prerequisite | Current state | Effect on approval |
|---|---|---|
| Candidate-specific signed artifact manifest | Pending protected artifact signer | Certification must deny. |
| Candidate-specific signed benchmark record | Pending protected benchmark signer | Certification must deny. |
| Independent approved security review | Preliminary review is rejected; SR-001 and SR-004 are high severity | Admission, certification, and GA must deny. |
| Shared and Dedicated real-host staging evidence | No protected real staging hosts or signer attached | Admission, certification, and GA must deny. |
| Six-decision Core adapter and signer policy | Does not exist for cross-repository host-isolation candidate | No records can be emitted. |

## Required forward integration

Do not merge host-isolation runtime, cage, terminal, namespace, mount, cgroup, or executable-control code into `core`. The required change is a narrowly scoped **Core policy integration** on the `core` branch, built only after the security review findings are remediated.

The new Core contract should bind the following identifiers in each decision: host-isolation repository identity, semantic release ID, full host-isolation source commit, artifact-manifest digest, SBOM digest, benchmark-evidence digest, security-review digest, edition-specific staging-evidence digest, Core policy digest, decision kind, issuer key ID, issuance/expiry, and canonical Ed25519 signature. It must define six unique required decisions: `shared/admission`, `shared/certification`, `shared/ga`, `dedicated/admission`, `dedicated/certification`, and `dedicated/ga`.

The Core integration must be a fail-closed policy authority with separate signer custody, durable replay/idempotency records, protected audit-before-response semantics, strict source/evidence binding, bounded expiry, and deterministic adversarial tests. Shared and Dedicated must consume immutable signed decisions; they must not generate or approve their own Core gates.

## Ordered continuation

1. Remediate SR-001 by binding Phase 8 evidence to the exact host-isolation release, source commit, artifact-manifest digest, and SBOM digest; then rerun all relevant regression tests.
2. Provision independent Shared and Dedicated staging hosts and protected signing/audit boundaries. Run all fifteen Phase 8 scenarios and retain two verified signed evidence records.
3. Complete protected artifact-manifest and benchmark-evidence signing. Obtain an independent **approved** security review with no unresolved release-blocking findings.
4. Implement and independently review the narrow Core cross-repository gate contract on the `core` branch. Keep `brick-host-isolation` as the engine authority and preserve the one-way Core branch model.
5. In the protected Core signer environment, evaluate the complete exact evidence bundle. Emit six current approved records only if every policy input is fresh, signature-valid, source-bound, and audit-recorded; otherwise retain signed denials.
6. Submit those six records to the Phase 9 certification authority and verify the final guarded-release certificate before an edition pin is considered.

> **Status:** `v1.0.0` is not admitted, certified, or GA-authorized by Core. Neither Shared nor Dedicated is permitted to pin or deploy this candidate.
