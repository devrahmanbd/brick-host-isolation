# Phase 2: Root-Owned Broker and Caller Authentication

## Scope and non-scope

Phase 2 implements the narrow local authorization broker that future Shared and Dedicated adapters use to request lifecycle authorization. The broker accepts only mutually authenticated TLS 1.3 connections over an owner-controlled Unix-domain socket. It validates the Unix peer UID, the verified client certificate, an exact SPIFFE URI SAN allowlist, the identity binding to the signed Phase 1 request, protocol size limits, a per-identity rate limit, host preflight, and the Phase 1 authority.

This phase **does not** create, mount, activate, suspend, destroy, or inspect a cage. It must not be used to claim real Linux isolation until Phase 3 through Phase 8 enforcement and staging evidence are complete.

## Required deployment state

| Control | Required state |
|---|---|
| Broker directory | Root-owned, not a symlink, and not group- or world-writable. |
| Socket | Absolute path under that directory; root-owned and mode `0600` or `0660`; no world access. |
| Client local identity | Unix peer UID allowlist **and** verified TLS 1.3 client certificate **and** exact SPIFFE URI SAN allowlist. |
| Server TLS | TLS 1.3 minimum, server certificate, client CA bundle, and `RequireAndVerifyClientCert`. |
| Dependencies | Durable owner-protected replay ledger, protected audit sink, clock, host preflight, and Phase 1 authority. |
| Limits | Bounded request/response frames, bounded connection pool, deadline, and configured per-identity token bucket. |

## Failure behavior

Every ambiguity is a denial or an unavailable result. The broker does not fall back to plaintext, an unverified certificate, an unverified peer UID, a permissive socket directory, an alternate identity, in-memory replay protection, or a best-effort audit write. No authorization response is emitted when its broker-level audit event cannot be stored.

The file replay ledger uses an advisory file lock, secure owner/mode checks, `O_NOFOLLOW`, bounded reads, atomic replacement, data sync, and directory sync. The ledger path and its parent must be on a durable local filesystem controlled by the broker owner; network filesystems and shared writable paths are prohibited.

## Key, certificate, and incident operations

Client identity changes require a staged certificate rollout, an explicit allowlist update, preflight validation, a verifier run, and audit review. Do not widen an allowlist to an organization prefix or a wildcard. A suspected client-key compromise requires removal of the exact SPIFFE identity and certificate issuer path, broker restart with reviewed configuration, ledger preservation for investigation, and a replacement identity rollout.

If the ledger, clock, audit sink, server certificate, client CA, socket ownership, or preflight is unavailable, stop admission and investigate the protected audit path. Do not delete the replay ledger to restore service; preserve it as incident evidence and use a reviewed recovery procedure.

## Verification and activation gate

Run the verifier from the repository root. It creates a temporary owner-restricted socket directory, a local test CA and SPIFFE client certificate, a durable replay ledger, and performs one actual mutually authenticated framed request through the broker.

```bash
go run ./cmd/broker-verify
bash ci/phase2-validate.sh
```

The expected messages are `host-isolation broker verification passed` and `Phase 2 root-broker validation passed.` These checks prove protocol and dependency handling only. They do not authorize deployment of a root broker on a customer host and do not validate a production TLS PKI, root UID deployment, host preflight implementation, namespaces, cgroups, mounts, seccomp, or network isolation.
