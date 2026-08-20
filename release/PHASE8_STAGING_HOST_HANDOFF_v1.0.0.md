# Phase 8 Real-Host Staging Handoff — v1.0.0

## Verified current blocker

On `2026-08-20`, the execution workspace was checked only for explicitly attached persistent or desktop host mounts and declared host metadata. No persistent host mount, desktop mount, Shared staging directory, Dedicated staging directory, protected release-evidence directory, or attached-host `agents.md` metadata was present. Consequently, this workspace has **no independently controlled real Shared or Dedicated staging host** and no configured protected Phase 8 evidence signer.

> No Phase 8 real-host scenario was run and no staging-evidence record was created. Local verifier fixtures, this development sandbox, and unsigned documents are not substitutes for the required independent staging evidence.

## Minimum host topology

| Boundary | Shared staging host | Dedicated staging host |
|---|---|---|
| Administrative identity | Separate host/operator identity from the release workspace and Dedicated staging. | Separate host/operator identity from the release workspace and Shared staging. |
| Runtime profile | Must compile and exercise only `shared-tenant`. | Must compile and exercise only `dedicated-administrator`. |
| Candidate binding | Deploy only the selected `v1.0.0` candidate at `b2ff94d6f8496bd9f14fe55cff651422b953d31c`, with recorded source/base-root/seccomp/profile bindings. | Deploy only the same selected candidate with separately recorded profile and host bindings. |
| Evidence custody | Write raw outputs to protected storage that the cage cannot modify; submit final evidence to the separate staging-evidence signer. | Same, with a distinct evidence collection identity and protected storage location. |
| Isolation | Must be a real disposable staged host/cage boundary, not a local unit-test process, simulator, or shared sandbox. | Same. |

The staging-evidence signer must be distinct from the artifact-manifest, benchmark-evidence, security-review, Core-gate, and certificate signers. Its **public** key must appear in the protected trust bundle; its private key must stay in the protected signer boundary.

## Required scenario matrix

Run the following fifteen mandatory scenarios once on each host. Each test must produce a stable evidence digest, protected raw output reference, pass/fail outcome, host identity, profile binding, and candidate binding. A failed, omitted, duplicated, unsigned, stale, or incorrectly bound observation invalidates that edition’s evidence.

| # | Mandatory scenario | Required safe assertion |
|---:|---|---|
| 1 | `pathTraversal` | Escape paths are rejected; a tenant cannot resolve outside the approved root. |
| 2 | `mountEscape` | Mount policy cannot expose an unapproved host or sibling path. |
| 3 | `symlinkEscape` | Symlink traversal cannot leave the approved root. |
| 4 | `bindMountEscape` | Bind-mount manipulation cannot create an unauthorized path. |
| 5 | `namespaceEscape` | Namespace boundaries cannot be joined, widened, or escaped. |
| 6 | `processEscape` | Cross-boundary process inspection/control is denied. |
| 7 | `socketExposure` | Unapproved Unix and network sockets are absent or inaccessible. |
| 8 | `environmentInjection` | Untrusted environment injection is rejected or stripped. |
| 9 | `executableInjection` | Unmanifested executable/interpreter replacement is denied. |
| 10 | `egressBypass` | Egress is default-denied except for explicitly authorised policy. |
| 11 | `resourceExhaustion` | Cgroup resource limits contain the test without degrading the host boundary. |
| 12 | `replayAttempt` | Replayed lifecycle/broker input is rejected. |
| 13 | `auditFailure` | An unavailable protected audit sink prevents authorization completion. |
| 14 | `freezeRecovery` | Recovery follows the signed kill-first/freeze evidence path without resuming unsafe execution. |
| 15 | `crossTenantIsolation` | A tenant cannot access, signal, mount, or observe another tenant boundary. |

## Controlled execution sequence

1. Prepare each disposable host independently and collect Phase 3 preflight/base-root evidence. Pin the candidate commit and expected Phase 4/5/6 plan digests before any scenario begins.
2. Configure mTLS/SPIFFE identities, root-owned broker ownership/mode, peer UID allowlist, rate limits, and the protected audit sink. Run only approved synthetic tenant identities and non-destructive fixtures.
3. Run all fifteen scenarios in the fixed order above. Capture raw output in the protected evidence store, and stop the host run on the first failure rather than masking it with a retry.
4. Construct one `brick.host-isolation.edition-evidence.v1` record per edition. Ensure the correct edition/profile, cage ID, binding digest, issuance time, full ordered observation set, and Ed25519 signature from the separate staging signer.
5. Independently verify both records against the pinned staging-evidence public key. Retain the signed evidence, raw outputs, audit correlation, host preflight data, and verifier result in protected storage.
6. Update the Phase 9 ceremony record with protected references only. Do not commit private keys, raw host paths, identities, tenant data, or confidential raw evidence into this repository.

## Acceptance record

The Phase 8 staging gate remains blocked until both rows are complete:

| Edition | Candidate/commit match | 15 ordered passes | Valid signing key | Protected evidence retention | Independent verification |
|---|---|---|---|---|---|
| Shared | Pending real host | Pending real host | Pending real host | Pending real host | Pending real host |
| Dedicated | Pending real host | Pending real host | Pending real host | Pending real host | Pending real host |
