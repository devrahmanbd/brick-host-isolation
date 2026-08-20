# Host Isolation Architecture

## Design objective

The runtime provides a narrow host-isolation service for workload cages. Shared and Dedicated policy compilers make distinct policy choices, but both pass through a common broker and common Linux enforcement pipeline. Core is deliberately outside this call path; it verifies the resulting signed evidence rather than controlling workloads directly.

```text
Shared policy compiler ──┐                         ┌── Signed minimal evidence ──> Core verifier
                         ├─ mTLS signed request ─> │
Dedicated policy compiler┘                         │
                                              Root-owned broker
                                                   │
                 ┌─────────────────────────────────┼──────────────────────────────────┐
                 │                                 │                                  │
          Host preflight                    Durable replay ledger                Protected audit sink
                 │                                 │                                  │
                 └─────────> Common Linux enforcement pipeline <───────────────────────┘
                                      │
                    namespaces → mounts → cgroup v2 → seccomp → egress → exec manifest
                                      │
                         Shared tenant cage or Dedicated administrator cage
```

## Exact lifecycle

1. An edition adapter creates a canonical request with a UUID request ID, short expiry, caller SPIFFE ID, profile, policy digest, cage ID, resource policy, mount plan, network policy, executable manifest digest, and signature.
2. The root-owned broker validates request size, timestamp window, caller workload identity, trusted signer, durable replay ledger, and audit availability before any host action.
3. Host preflight validates the required kernel and operating-system capabilities, verifies no protected Brick asset is eligible for the mount plan, and verifies the immutable base root and executable manifest.
4. The broker creates the private namespaces, controlled UID/GID mappings, cgroup v2 subtree, restricted mounts, private network namespace, default-deny egress policy, seccomp program, and sanitized execution environment.
5. The broker audits activation and returns a signed minimal attestation. It never returns host paths, secrets, raw policy, or control-plane details to the caller.
6. A violation, stale state, audit failure, replay failure, cgroup breach, policy drift, or high-severity signal freezes or kills the cage first, withdraws network access, preserves protected evidence, and then reports the denied/suspended outcome.

## Profile differences

| Field | Shared tenant profile | Dedicated administrator profile |
|---|---|---|
| Principal | One tenant workload/session | One customer administrator workload/session |
| Root | Tenant-specific immutable cage root | Customer tool root, still excluding all protected Brick assets |
| Commands | Minimal tenant command manifest | Signed, reviewed administrator tool manifest |
| Network | Denied except explicit application/provider egress | Denied except explicit management/application egress |
| Resource model | Per-tenant fixed quota and anti-abuse limits | Customer plan quota with stricter break-glass approval for expansion |
| Break-glass | Forbidden | Two-person, short-lived, recorded profile only; never host root |

## Mandatory Linux layers

The engine must require, rather than merely offer, cgroup v2 resource control, separate namespaces, mount propagation restrictions, `no_new_privs`, capability dropping, seccomp filtering, executable verification, and network isolation. Linux cgroup v2 provides hierarchical resource control; seccomp constrains system-call exposure; and systemd execution controls can help supply process-level hardening primitives.[1] [2] [3]

The design intentionally rejects partial activation. For example, a successful cgroup setup does not authorize a cage if seccomp, replay protection, the audit sink, or the protected-path exclusion has failed.

## Repository and release flow

This repository is private and independently protected. A release must include a source commit, immutable tag, signed build artifact, digest, SBOM, vulnerability review, unit/race/static results, staging escape-suite evidence, and an operational runbook. Shared and Dedicated pin the version and digest; they must not vendor or fork the engine.

## Non-goals

The engine is not a general container platform, tenant shell, Docker manager, panel API, package manager, or guarantee against kernel compromise. It must not claim that code can prevent theft after host-root compromise. The correct response to a compromised host is containment, evidence preservation, clean rebuild, key rotation, and re-attestation.

## References

[1]: https://docs.kernel.org/admin-guide/cgroup-v2.html "Linux kernel: Control Group v2"
[2]: https://man7.org/linux/man-pages/man2/seccomp.2.html "Linux manual page: seccomp(2)"
[3]: https://www.freedesktop.org/software/systemd/man/systemd.exec.html "systemd.exec — Execution environment configuration"
