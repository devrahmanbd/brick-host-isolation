# Phase 8: Edition Adapters and Staging Evidence

## Scope

Phase 8 supplies the only reusable adapter layer for **Brick Shared** and **Brick Dedicated**. It compiles a small edition intent into the existing Phase 4 isolation request, Phase 5 resource request, and Phase 6 execution request. It has no root privileges, does not invoke the broker, and never forks, copies, or reimplements the host-isolation engine.

Both editions use the exact same immutable engine contracts. The compiler chooses only an audited, preconfigured edition template: profile, bounded resource template, default-deny egress template, fixed executable path, and fixed argument vector. It cannot accept raw mount sources, device paths, namespace choices, capabilities, egress rules, commands, interpreter paths, or environment values from an edition caller.

## Binding controls

| Stage | Required proof |
|---|---|
| Edition compile | Exact edition/profile pairing, versioned intent, cage ID, base-root digest, seccomp digest, and canonical compilation digest. |
| Resource bind | Independently verified Phase 4 plan with matching cage and profile. |
| Execution bind | Independently verified Phase 5 plan with matching cage and profile. |
| Staging evidence | A complete, signed fifteen-scenario matrix tied to the compilation digest. |

The deterministic matrix requires successful evidence for path traversal, mount/symlink/bind-mount/namespace/process escape, socket exposure, environment and executable injection, egress bypass, resource exhaustion, replay, audit failure, freeze recovery, and cross-tenant isolation. A missing, reordered, failing, malformed, unsigned, or tampered observation denies evidence issuance.

## Operational gate

The included runner is a contract boundary, not a production penetration-test harness. A production runner must execute each scenario against isolated staging infrastructure, emit a content-addressed evidence digest to protected storage, and preserve all lower-phase attestation and release evidence. Do not use a unit-test runner as staging certification.

Shared and Dedicated adapters must pin one immutable signed host-isolation release and retain the exact compilation/evidence digests used for every admission. They may upgrade to a reviewed release but must never fork engine code or merge edition runtime code into Core.

```bash
go run ./cmd/edition-verify
bash ci/phase8-validate.sh
```

The standalone verifier validates the contract, compiles a Shared intent using a preconfigured template, runs all required deterministic scenarios, signs evidence, and verifies the evidence signature. It does not certify a real host.
