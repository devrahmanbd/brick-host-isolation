# Brick Host Isolation — Implementation Backlog

## Bootstrap — Governance and Architecture

- [x] Establish the private repository boundary, governance rules, security policy, architecture, versioned lifecycle contract, and implementation backlog without adding host-runtime code to Core, Shared, or Dedicated.

## Phase 0 — Repository and supply-chain baseline

- [ ] Add a Go module, reproducible build metadata, formatting/lint targets, unit-test and race-test scripts, license posture, code-owner rules, signed-tag policy, SBOM generation, and protected CI workflow.
- [ ] Define the trusted release signing-key rotation process, provenance requirements, vulnerability response window, and artifact-retention policy.

## Phase 1 — Versioned lifecycle and attestation contract

- [x] Implement `brick-host-isolation.v1` strict schema, shape, policy, time-window, signature-algorithm, and protected-path validation for create, activate, suspend, destroy, and attest requests.
- [x] Require caller SPIFFE identity, policy digest, request ID, issuance/expiry, profile name, cgroup limits, mount plan, executable manifest, default-deny network policy, and protected audit target in every authorization request.
- [x] Define canonical Ed25519-signed lifecycle request and attestation envelopes with replay identifiers and monotonic authorization sequences.
- [x] Implement a fail-closed lifecycle authority that validates configured caller keys, atomically claims request IDs, records every decision, and produces minimal signed authorization evidence.
- [x] Add deterministic adversarial tests, a standalone verifier, the Phase 1 operational runbook, a release-gate script, and a GitHub Actions workflow job.
- [ ] Demonstrate the contract with a durable replay ledger and audit sink in a dedicated staging environment; do not activate a cage from Phase 1 authority alone.

## Phase 2 — Root-owned broker and caller authentication

- [x] Build the broker over an owner-controlled Unix socket with TLS 1.3 mTLS, exact SPIFFE URI SAN authentication, Unix peer-UID checks, socket ownership checks, a durable replay ledger, bounded request/response frames, rate limits, cancellation, and audit-before-response behavior.
- [x] Fail closed if workload identity, Phase 1 authority, audit sink, replay store, clock, socket ownership, TLS client CA, or host preflight requirements are unavailable.
- [x] Add deterministic broker and ledger adversarial tests, a standalone mTLS Unix-socket verifier, a Phase 2 runbook, release gate, and GitHub Actions job.
- [ ] Demonstrate the broker under a root-owned production-like service manager with the production TLS PKI, durable local ledger storage, real host preflight, and an audited failure-recovery drill before using it for a lifecycle side effect.

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
