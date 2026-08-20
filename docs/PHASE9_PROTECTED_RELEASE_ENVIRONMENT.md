# Phase 9 — Protected Release Environment Provisioning

## Scope and current limitation

The Phase 9 authority needs a protected environment because its trust roots, certificate private key, broker, audit sink, and evidence store are security boundaries. The development sandbox is **not** an acceptable production release environment: no persistent release host is attached to this session, the sandbox must not hold production private keys, and no durable protected audit/evidence service is configured here. This document is therefore a provisioning specification and acceptance procedure, not a claim that the environment is already live.

The environment must remain separate from tenant hosts, Shared and Dedicated cages, build workers, review workstations, and general CI. An authorization compromise in any of those domains must not expose certificate signing ability or permit rewriting evidence.

## Minimum control plane

| Component | Required placement and identity | Failure behavior |
|---|---|---|
| Release authority | Dedicated hardened service identity with access only to its certificate signer and public verification bundle. | Cannot issue if any dependency, policy, signer, clock, or audit write fails. |
| Broker | Root-owned Unix-domain socket directory with a narrowly scoped service UID, peer-UID allowlist, TLS 1.3 mTLS, and exact SPIFFE allowlist. | Rejects untrusted UID/identity, malformed input, failed preflight, rate-limit exhaustion, or unavailable audit. |
| Signers | Six separately administered non-exportable Ed25519 signing roles, preferably independent KMS/HSM policies. | A role can sign only its typed record; compromise/revocation blocks affected new certifications. |
| Audit store | Protected append-only event system with sequence/integrity protection and restricted write/read identities. | An unavailable, rejected, or non-durable write blocks authorization/certification. |
| Evidence store | Encrypted immutable/WORM retention with isolated writer and reviewer roles, integrity checks, backup, retention hold, and restoration drill. | Missing, unreadable, altered, or expired evidence blocks pinning. |
| Time/revocation | Trusted UTC time source and protected signer/review revocation distribution. | Time failure, expiry, or revocation ambiguity blocks issuance. |

The Go broker already enforces the local transport properties required by this deployment profile: it validates a root-owned non-symlink socket directory, exact socket ownership/mode, peer UID, TLS 1.3 client-certificate authentication, exact SPIFFE identity, framing limits, rate limiting, host preflight, and audit-before-response. Its deployment configuration must supply those dependencies; the current source authority does not substitute for a provisioned protected host.

## Provisioning sequence

1. Allocate a persistent, hardened host or equivalent managed control plane distinct from development, tenant, and CI systems. Enforce narrowly scoped administrative access, OS patching, encrypted storage, restricted egress, and monitored time synchronization.
2. Establish six role-separated signing policies and fill `KEY_CUSTODY_INVENTORY.template.md` with **references only**. Keep private material non-exportable and outside source control.
3. Instantiate `TRUST_BUNDLE.public.template.json` in the protected configuration system. Populate only public keys and non-secret key identifiers, set the candidate ID and full SHA exactly, and pin a one-hour certificate TTL and 24-hour maximum evidence age.
4. Deploy the broker as a least-privileged service behind its root-owned socket directory. Configure the actual intended service UID, exact SPIFFE identities, TLS 1.3 client CA, request/response bounds, timeout, connection cap, and rate limit. Do not expose this socket to tenant or build workloads.
5. Deploy protected audit and evidence stores with distinct writer, verifier, reviewer, and retention-administrator identities. Enforce append-only sequence/integrity protection for audit events and immutable retention for evidence objects.
6. Execute every row in `ENVIRONMENT_ACCEPTANCE.template.md` using harmless synthetic identities and fixture evidence. Record only protected evidence references in the completed acceptance record.
7. Obtain an independent security approval of the completed acceptance record. Only then move to the actual candidate evidence ceremony.

## Mandatory health and audit-write tests

Broker health is not a bare network-port probe. It must prove the broker applies its real admission controls: validated root-owned socket state, mTLS handshake, exact SPIFFE mapping, accepted peer UID, preflight success, rate-limit behavior, and audit-before-response. Test an approved synthetic identity and adversarial inputs separately. The success check is valid only when the protected audit store contains the exact correlated authorized record; the denial checks are valid only when their denied records are also present.

The audit-write test must be a new synthetic event linked to the selected candidate, not a generic log line. Verify a durable store-assigned reference or sequence, immutable event payload/digest, actor, action, outcome, UTC time, and later read-back by a separately authorized verifier identity. Then disable or deny audit writes in a controlled maintenance window and prove both broker and certificate authority fail closed without returning an authorization or certificate. Restore the audit sink and retain both test records.

## Non-negotiable prohibitions

Do not generate production private keys in this repository, the development sandbox, CI variables, developer home directories, issue trackers, chat transcripts, or general shared storage. Do not reuse a key role, bypass an unavailable audit dependency, permit a tenant or build identity to call the release authority, or accept an unsigned template as evidence. Do not mark the Phase 9 environment item complete until independent acceptance evidence exists in the protected store.
