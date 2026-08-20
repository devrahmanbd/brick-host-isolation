# Post-Pin Revoke and Recovery Drill Handoff — v1.0.0

## Current execution status

This drill has **not** run. Candidate `v1.0.0` has no valid Phase 9 certificate, no Shared or Dedicated pin, no approved deployment change, no attached independently controlled non-customer staging cage, no protected revocation authority, and no protected audit/evidence store. A local fixture run would not prove signer revocation, pin denial, or Phase 7 host recovery and must not be recorded as an incident drill.

No customer, production host, tenant workload, signer, or review record may be touched by this exercise. The drill must be run only after a valid pin exists, on a disposable explicitly labelled non-customer cage under an approved maintenance window.

## Recommended drill mode

Use an **isolated review-expiry drill** first. It is safer than revoking a shared production signer because it changes only a dedicated test review record. Create the test review with a short expiry, complete a successful pre-expiry verification baseline, advance trusted test time beyond expiry, and submit a new pin authorization request. The expected outcome is denial before any certificate, pin, or deployment authorization is returned.

After the expiry drill passes, run an optional isolated signer-revocation drill using a test-only signer key ID in a test-only trust bundle revocation list. Do not revoke a shared production key during the first drill.

## Entry criteria

| Required control | Required evidence |
|---|---|
| Existing pin | A valid independently verified guarded-release certificate and an immutable pin for the selected test edition/candidate. |
| Cage scope | Dedicated disposable `cage-*` staging cage marked non-customer; no production mounts, sockets, credentials, tenant data, or shared control-plane access. |
| Change authorization | Approved staging-only change request, explicit start/stop window, rollback target, and named incident commander. |
| Trust separation | Test review/signer and trust bundle are segregated from production signing roles. |
| Recovery authority | Protected Phase 7 signer, journal, audit sink, evidence store, cage controller, and rebuild handoff are configured for only the fixed test cage. |
| Audit retention | Immutable protected audit and evidence destinations are live, independently readable, and preflight-verified. |
| Observation controls | Independent observer has read-only access to protected audit/evidence, trust/revocation state, pin authorization response, and recovery attestation. |

## Execution sequence

1. Record the valid baseline pin, certificate digest, edition/profile binding, source commit, expected policy digest, test-cage identity, evidence references, and rollback target in protected staging change control. Confirm independent certificate verification and prior audit retention.
2. Run a baseline authorization check with the still-valid test review. Record success only as a precondition; do not deploy customer workload or mutate production state.
3. Expire the dedicated test review by advancing only the isolated trusted test clock past its recorded expiry. Alternatively, revoke the isolated test signer key ID through the protected test revocation authority. Record the signed/immutable revocation-or-expiry event and correlation.
4. Submit a fresh authorization/pin attempt with the same candidate evidence and a new broker/certificate request ID. Verify that no new guarded-release certificate, edition pin, or deployment approval is returned. Verify the broker/replay/audit denial record and decision reason through protected read-only evidence.
5. Declare the disposable test cage unsafe because its governing approval is no longer valid. Invoke `recovery.SuspendAndRecover` only through the protected Phase 7 authority using a fresh recovery UUID, the fixed test `cage-*` identity, the bound `host-*` identity, expected policy digest, and `policyViolation` reason code.
6. Verify the exact kill-first sequence: `recordRequest/accepted`, `kill/completed`, `freeze/completed`, `withdrawNetwork/completed`, `captureEvidence/completed`, `destroy/completed`, then `cleanRebuildHandoff/completed`. The authority must not progress past a failed step.
7. Independently verify every signed recovery event, the final signed `recoveryCompleted` attestation, sequence order, evidence digest, fixed cage identity, and protected journal/audit read-back. Confirm that no old process, socket, mount, network path, or workload state survives the destroy/rebuild boundary.
8. Record remediation confirmation only if every denial and recovery assertion passed. The test cage may be rebuilt as new staging infrastructure; it must not be resumed under the expired/revoked approval. Any unexpected certificate, pin, approval, missing audit record, sequence deviation, or recovery failure is an incident and blocks customer activation.

## Required protected incident-drill record

The protected evidence store—not this repository—must retain the following digest-bound references:

| Evidence class | Required content |
|---|---|
| Baseline | Certificate/pin verifier receipt, candidate/edition/profile binding, change approval, and baseline audit correlation. |
| Revocation or expiry | Test review/signing-key identifier, signed revocation or test-time evidence, immutable correlation, and observer confirmation. |
| Halt proof | New request ID, denied authorization response, absence of a returned certificate/pin/approval, broker/replay record, and audit correlation. |
| Recovery | Recovery request, signed ordered events, evidence-capture digest, signed attestation, journal/audit read-back, cage destruction confirmation, and clean rebuild handoff. |
| Remediation | Independent observer decision, residual-risk decision, corrective actions, reopen criteria, and customer-activation status. |

## Current blocker and continuation

The drill cannot begin until a valid certificate and edition pin are created under the Phase 9 ceremony. Before then, there is no post-pin state to revoke and no legitimate deployment authority to halt. The prerequisites remain blocked by SR-001 remediation, protected evidence signing, independent real-host staging, independent approved review, Core six-gate integration, certificate issuance, and pin approval.

> **Fail-closed conclusion:** No incident drill record or remediation confirmation exists yet. Customer activation remains prohibited.
