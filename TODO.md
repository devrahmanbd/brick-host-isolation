# Brick Host Isolation — Implementation Backlog

## Bootstrap — Governance and Architecture

- [x] Establish the private repository boundary, governance rules, security policy, architecture, versioned lifecycle contract, and implementation backlog without adding host-runtime code to Core, Shared, or Dedicated.

## Phase 0 — Repository and supply-chain baseline

- [ ] Add a Go module, reproducible build metadata, formatting/lint targets, unit-test and race-test scripts, license posture, code-owner rules, signed-tag policy, SBOM generation, and protected CI workflow.
- [ ] Define the trusted release signing-key rotation process, provenance requirements, vulnerability response window, and artifact-retention policy.

## Phase 1 — Versioned lifecycle and attestation contract

- [ ] Implement `brick-host-isolation.v1` parsing and strict validation for create, activate, suspend, destroy, and attest requests.
- [ ] Require caller SPIFFE identity, policy digest, request ID, issuance/expiry, profile name, cgroup limits, mount plan, executable manifest, network policy, and attestation target in every activation request.
- [ ] Define the signed attestation, policy-result, and suspension-event envelopes with canonical serialization and replay identifiers.

## Phase 2 — Root-owned broker and caller authentication

- [ ] Build the broker over a root-owned Unix socket with mTLS/SPIFFE authentication, socket ownership checks, durable replay ledger, bounded request size, rate limits, cancellation, and audit-before-response behavior.
- [ ] Fail closed if workload identity, policy signer, audit sink, replay store, clock, or host preflight requirements are unavailable.

## Phase 3 — Linux host preflight and immutable base root

- [ ] Validate kernel, cgroup v2 unified hierarchy, user namespaces, seccomp support, LSM posture, mount propagation, time source, protected-path permissions, and required system services before any cage activation.
- [ ] Create a root-owned read-only base image and a per-cage ephemeral writable layer. Reject host paths, writable protected mounts, symlinks, device nodes, setuid files, and unsafe mount propagation.

## Phase 4 — Namespace, mount, process, and capability boundaries

- [ ] Create isolated user, PID, mount, IPC, UTS, and network namespaces with explicit UID/GID mapping and no inherited process, file descriptor, environment, or capability state.
- [ ] Enforce `no_new_privs`, a minimal capability set, filtered `/proc`, restricted `/dev`, controlled `/tmp`, strict mount flags, and a tested seccomp allow-list per profile.

## Phase 5 — Cgroup v2 and default-deny network enforcement

- [ ] Apply hard CPU, memory, swap, I/O, process, file-descriptor, and wall-clock controls under a broker-owned cgroup v2 subtree.
- [ ] Create a private network namespace with no direct host network path; require a policy-aware egress proxy or deny all egress.

## Phase 6 — Executable and environment integrity

- [ ] Verify every executable and interpreter against a root-owned manifest of fixed path, digest, arguments, ownership, mode, and approved library/runtime environment.
- [ ] Clear unsafe environment variables, cwd inheritance, PATH lookup, locale/plugin injection, language-specific preload hooks, and user-controlled dynamic-loader paths.

## Phase 7 — Audit, attestation, freeze, and recovery

- [ ] Emit signed, append-oriented lifecycle and violation events; include policy digest, cage ID, caller identity, host identity, monotonic sequence, outcome, and redacted reason code.
- [ ] Implement kill-first suspension, cgroup freeze, network withdrawal, evidence capture, secure destroy, and clean-rebuild handoff for anomalous cages.

## Phase 8 — Edition adapters and staging evidence

- [ ] Implement the Shared profile compiler for tenant cages and the Dedicated profile compiler for customer administrator cages without duplicating engine code.
- [ ] Build deterministic staging tests for path, mount, symlink, bind-mount, namespace, process, socket, environment, executable, egress, resource, replay, audit-failure, freeze, recovery, and cross-tenant cases.

## Phase 9 — Certification and guarded release

- [ ] Produce a standalone verifier, CI gate, operational runbook, SBOM, signed artifact manifest, benchmark evidence, and security review record.
- [ ] Allow editions to pin a release only after the mandatory staging evidence and their existing Core admission/certification/GA policy gates are satisfied.
