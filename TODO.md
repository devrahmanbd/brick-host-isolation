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

- [x] Emit Ed25519-signed append-oriented lifecycle and violation events containing policy digest, cage ID, caller identity, host identity, monotonic sequence, outcome, redacted reason code, and an optional evidence digest; reject event tampering.
- [x] Implement fail-closed kill-first suspension orchestration with cgroup freeze, network withdrawal, evidence capture, secure destroy, and clean-rebuild handoff ordering for anomalous cages; require journal and audit acceptance before the first side effect.
- [x] Add deterministic adversarial recovery tests, a standalone verifier, Phase 7 runbook, release gate, and GitHub Actions job.
- [ ] Implement and independently validate root-owned cage-controller, evidence-store, and rebuild-handoff adapters; demonstrate recovery order, no-resume behavior, evidence durability, restart safety, audit/journal outage behavior, secure destroy, and clean-rebuild isolation on an isolated staging host before operational activation.

## Phase 8 — Edition adapters and staging evidence

- [x] Implement the Shared profile compiler for tenant cages and the Dedicated profile compiler for customer administrator cages without duplicating engine code or accepting raw engine controls from edition callers.
- [x] Build deterministic signed staging evidence for path, mount, symlink, bind-mount, namespace, process, socket, environment, executable, egress, resource, replay, audit-failure, freeze, recovery, and cross-tenant cases.
- [x] Add adversarial compiler and staging-evidence tests, a standalone verifier, Phase 8 runbook, release gate, and GitHub Actions job.
- [ ] Operate the staging matrix against real isolated Shared and Dedicated hosts using an independent scenario runner and protected evidence store; require security review of signed evidence before either edition accepts tenant workloads.

## Phase 9 — Certification and guarded release

- [x] Implement the `brick.host-isolation.certification.v1` contract and fail-closed authority that verifies signed artifact-manifest/SBOM linkage, benchmark evidence, independent security review, Shared and Dedicated Phase 8 staging evidence, and all existing Core admission/certification/GA gates before issuing an expiring Ed25519-signed guarded-release certificate.
- [x] Add deterministic adversarial tests, a standalone verifier, Phase 9 operational runbook, SBOM/artifact-manifest/security-review templates, release-gate script, and GitHub Actions job.
- [x] Select and record an immutable `main` release candidate with a semantic release identifier and verified full commit SHA; this record is not signed production-release evidence. Candidate: `v1.0.0` at `b2ff94d6f8496bd9f14fe55cff651422b953d31c` in `release/RELEASE_CANDIDATE_v1.0.0.md`.
- [ ] Provision the protected release environment outside the development sandbox: separate Ed25519 signer custody, pinned trust-bundle configuration, authenticated rate-limited broker, append-only protected audit/evidence store, and independently verified health and audit-write checks.
- [x] Build `v1.0.0` from `b2ff94d6f8496bd9f14fe55cff651422b953d31c` in an isolated worktree and generate the actual CycloneDX SBOM, SHA-256 digests, and ordered pre-signing artifact manifest. The complete unsigned build transcript is recorded in `release/PRELIMINARY_CANDIDATE_BUILD_v1.0.0.md`; artifacts remain outside source control pending protected-store transfer.
- [ ] Submit the exact `v1.0.0` artifact bytes, SBOM, and ordered pre-signing payload to the separately controlled artifact-manifest signer; retain and independently verify the resulting valid `brick.host-isolation.artifact-manifest.v1` Ed25519-signed record in the protected evidence store.
- [x] Run reproducible Phase 9 certification benchmark repetitions from the detached `v1.0.0` candidate worktree and bind the environment and result digests to `b2ff94d6f8496bd9f14fe55cff651422b953d31c`. The complete unsigned transcript and verification result are recorded in `release/PRELIMINARY_BENCHMARK_EVIDENCE_v1.0.0.md`; raw evidence remains outside source control pending protected-store transfer.
- [ ] Submit the exact `v1.0.0` raw benchmark output, environment record, and pre-signing payload to the separately controlled benchmark-evidence signer; retain and independently verify the resulting valid `brick.host-isolation.benchmark-evidence.v1` Ed25519-signed record in the protected evidence store.
- [ ] **Blocked pending real host attachment:** Run the full Phase 8 scenario matrix independently on real isolated Shared and Dedicated staging hosts, retain two protected valid signed `brick.host-isolation.edition-evidence.v1` records with no failed or omitted mandatory scenario, and independently verify them against the pinned staging-evidence public key. The verified current environment has no attached protected staging hosts or signer; use `release/PHASE8_STAGING_HOST_HANDOFF_v1.0.0.md` when the real hosts are available.
- [ ] Perform a separately controlled security review over the exact `v1.0.0` artifact manifest, certification engine, and Phase 8 staging-evidence records; retain a signed approved `brick.host-isolation.security-review.v1` record with short expiry, findings digest, and protected audit correlation. Preliminary local assessment must not be represented as independent sign-off.
- [x] Complete a preliminary evidence-based assessment over the selected candidate’s artifact-manifest, engine, and staging-evidence boundaries. The result is intentionally **rejected**, not approved: `release/PRELIMINARY_SECURITY_REVIEW_v1.0.0.md` records high-severity candidate-binding and real-host-evidence gaps plus medium replay and protected-artifact-verification gaps.
- [ ] Remediate SR-001 by cryptographically binding signed Phase 8 evidence to the Phase 9 candidate identity and rejecting mismatches; add deterministic adversarial coverage, regenerate both real-host records, and re-review before any approved security review is requested.
- [ ] Enforce SR-002 by proving the Phase 2 replay-resistant broker is the only certification ingress and by adding durable certificate-ID issuance/idempotency coverage; do not expose the authority directly in production.
- [x] Assess the existing Core release authorities for the selected candidate without modifying Core boundaries. `release/CORE_GATE_HANDOFF_v1.0.0.md` records that Phase 12, 48, 49, and 50 cannot emit the requested six cross-repository decisions: the present authorities are Core/Shared-beta scoped, no Dedicated gate exists, the candidate evidence is incomplete, the preliminary review is rejected, and no protected Core signer is attached.
- [ ] **Blocked pending remediation and Core policy integration:** Obtain six current protected Core gate records for exact candidate `v1.0.0` at `b2ff94d6f8496bd9f14fe55cff651422b953d31c`: Shared and Dedicated each require approved, unexpired, Ed25519-signed `admission`, `certification`, and `ga` decisions from the separately controlled Core policy authority. Do not substitute fixtures, local signatures, or edition-generated decisions.
- [x] Assess guarded-release submission readiness without attempting an unsafe request. `release/GUARDED_RELEASE_SUBMISSION_HANDOFF_v1.0.0.md` records that no production broker/trust/audit/evidence service is attached and every mandatory evidence class remains invalid, unsigned, absent, rejected, or unavailable for the selected candidate.
- [ ] **Blocked pending complete protected evidence and broker availability:** Submit only a complete, valid, independently signed `v1.0.0` evidence bundle to the authenticated, rate-limited protected Phase 9 broker; verify any returned guarded-release certificate with the pinned certificate public key and retain the request, all inputs, certificate, verifier result, and protected audit correlation. Do not submit unsigned or rejected preliminary records.
- [ ] Execute the protected release ceremony for a real immutable candidate: produce and sign the actual SBOM, artifact manifest, benchmark evidence, security review record, both staging records, and six Core gate records; retain them with the certificate before either edition pins the release.
