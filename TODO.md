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

- [x] Validate kernel, cgroup v2 unified hierarchy, user namespaces, seccomp support, actively enforcing LSM posture, mount propagation, time source, protected-path permissions, and required system services before broker authorization can proceed.
- [x] Validate a root-owned immutable base image and create a per-cage ephemeral `upper`/`work` layer pair. Reject unsafe managed paths, unsafe filesystems, writable protected entries, symlinks, device nodes, setuid/setgid files, unexpected ownership, and unsafe mount propagation.
- [x] Add deterministic adversarial preflight and base-root tests, a standalone verifier, operational runbook, release-gate script, and GitHub Actions job.
- [ ] Demonstrate actual root-owned base-image provisioning, production filesystem allowlisting, LSM enforcement, and preflight-driven broker denial/recovery on an isolated staging host before any cage mount or activation.

## Phase 4 — Namespace, mount, process, and capability boundaries

- [x] Define a strict namespace, mount, process, capability, descriptor, device, and seccomp plan that requires isolated user, PID, mount, IPC, UTS, and network namespaces; explicit non-root UID/GID mapping; and no inherited process state, descriptors, environment, or capabilities.
- [x] Require `no_new_privs`, empty capability bounding set, filtered `/proc`, restricted `/dev`, bounded `/tmp`, strict mount flags, a supervised reaper, parent-death signaling, and a SHA-256 seccomp profile digest per profile.
- [x] Add deterministic adversarial tests, a standalone plan verifier, Phase 4 operational runbook, release gate, and GitHub Actions job.
- [ ] Implement and independently validate a root-owned atomic executor, then demonstrate namespace, descriptor, environment, process, device, mount, and capability escape resistance on an isolated staging host before it creates a customer workload.

## Phase 5 — Cgroup v2 and default-deny network enforcement

- [x] Define and validate hard CPU, memory, swap, I/O, process, file-descriptor, and wall-clock controls under the fixed broker-owned cgroup v2 subtree; emit only a complete canonical controller-write sequence.
- [x] Define and validate default-deny network policy. `proxyOnly` requires a private network namespace, exact proxy SPIFFE identity, HTTPS-only port-443 endpoint allowlist, and no direct host network path.
- [x] Add deterministic adversarial resource-policy tests, a standalone verifier, Phase 5 runbook, release gate, and GitHub Actions job.
- [ ] Implement and independently validate the root-owned cgroup v2 filesystem adapter and private-network executor, then demonstrate limit enforcement, cleanup, no-host-route, no-DNS-bypass, proxy outage, and fail-closed egress recovery on an isolated staging host before a workload is admitted.

## Phase 6 — Executable and environment integrity

- [x] Verify every executable, interpreter, and runtime dependency against an Ed25519-signed root-owned manifest of fixed path, SHA-256 digest, arguments, ownership, mode, and approved runtime environment; bind every plan to a verified Phase 5 resource plan.
- [x] Forbid unsafe environment variables, cwd inheritance, `PATH` lookup, locale/plugin injection, language preload hooks, shell startup state, and user-controlled dynamic-loader paths; emit an exact minimal execution environment and descriptor-close boundary.
- [x] Add deterministic adversarial integrity tests, a standalone verifier, Phase 6 runbook, release gate, and GitHub Actions job.
- [ ] Implement and independently validate a root-owned descriptor-based executor that rechecks the actual opened executable, interpreter, and runtime dependencies immediately before `execve`; demonstrate TOCTOU, symlink, loader, environment, descriptor, and argument-injection resistance on an isolated staging host before running a workload.

## Phase 7 — Audit, attestation, freeze, and recovery

- [ ] Emit signed, append-oriented lifecycle and violation events; include policy digest, cage ID, caller identity, host identity, monotonic sequence, outcome, and redacted reason code.
- [ ] Implement kill-first suspension, cgroup freeze, network withdrawal, evidence capture, secure destroy, and clean-rebuild handoff for anomalous cages.

## Phase 8 — Edition adapters and staging evidence

- [ ] Implement the Shared profile compiler for tenant cages and the Dedicated profile compiler for customer administrator cages without duplicating engine code.
- [ ] Build deterministic staging tests for path, mount, symlink, bind-mount, namespace, process, socket, environment, executable, egress, resource, replay, audit-failure, freeze, recovery, and cross-tenant cases.

## Phase 9 — Certification and guarded release

- [ ] Produce a standalone verifier, CI gate, operational runbook, SBOM, signed artifact manifest, benchmark evidence, and security review record.
- [ ] Allow editions to pin a release only after the mandatory staging evidence and their existing Core admission/certification/GA policy gates are satisfied.
