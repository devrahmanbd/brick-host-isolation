# Brick Host Isolation

`brick-host-isolation` is the private, reusable Linux host-isolation boundary for Brick Shared and Brick Dedicated. It will provide a versioned, signed runtime engine for cage lifecycle management, host attestation, and isolation enforcement. It is **not** the Brick control plane and must never contain panel UI, customer records, billing, tenant business logic, Core services, or customer-facing management binaries.

The repository exists to ensure that Shared and Dedicated use **one reviewed enforcement engine** rather than forked copies. Each edition owns only a narrow adapter that compiles its edition policy into a signed `brick-host-isolation.v1` request. The runtime returns a minimal signed attestation that Core can consume as evidence without importing, running, or owning the host implementation.

| Boundary | Responsibility |
|---|---|
| `core` | Verifies signed evidence; makes admission, certification, and expansion decisions. |
| `brick-host-isolation` | Enforces host-level workload isolation and signs minimal attestation evidence. |
| `shared` | Compiles tenant-cage policy, quota, command, and egress policy for a Shared tenant. |
| `dedicated` | Compiles customer administrator-cage policy, tool manifest, and break-glass policy. |

## Security model

The future runtime is **default deny**. It must use a root-owned broker with mutually authenticated callers, a durable replay ledger, immutable signed policy input, controlled namespace and cgroup lifecycle, a read-only base root, verified executable manifests, constrained network access, structured audit export, and kill-first suspension. A failed invariant must deny creation or activation and emit an auditable event.

> A workload cage is a defense-in-depth boundary, not a substitute for host patching or hardware/VM separation. Host-root access or a kernel compromise is outside a cage’s security guarantee. Protected Brick paths, control-plane sockets, source, signing keys, and binaries must never be mounted into a customer workload.

## Release and consumption

No edition may consume an unversioned branch tip. Releases must be immutable, signed, SBOM-backed, independently reviewed, and pinned by version plus digest in the edition adapter. Shared and Dedicated may update their pinned engine version only after the host-isolation staging gate and their own branch gates pass.

The implementation plan is maintained in [TODO.md](TODO.md). The versioned lifecycle boundary is in [contracts/brick-host-isolation.v1.json](contracts/brick-host-isolation.v1.json). Architecture, staging evidence, and references are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
