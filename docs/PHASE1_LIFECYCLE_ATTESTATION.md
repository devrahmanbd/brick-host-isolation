# Phase 1: Signed Lifecycle and Attestation Authority

## Purpose

Phase 1 creates the fail-closed authorization boundary for future host-isolation lifecycle actions. It does **not** create a cage, invoke a privileged process, mount a filesystem, configure a namespace, or execute a customer command. Those effects remain prohibited until later phases add and validate the root-owned broker and Linux enforcement layers.

The authority accepts a short-lived Ed25519-signed request from a configured adapter workload identity and produces only a minimal Ed25519-signed attestation. The future broker must require this authorization immediately before any privileged lifecycle side effect.

## Preconditions

| Requirement | Required state |
|---|---|
| Adapter caller | Exact configured SPIFFE identity and trusted Ed25519 public key. |
| Request | Canonical signed envelope, valid UUID, exact policy digest, valid profile, bounded expiry, non-replayed request ID. |
| Policy containers | Positive resource limits, mandatory enforcement-layer set, safe read-only mount declarations, default-deny network policy, trusted executable-manifest digest, and protected audit target. |
| Dependencies | Durable replay ledger, writable audit sink, trusted engine signing key, and monotonic UTC clock. |

## Authorization and failure behavior

Every denial is audited before it is returned. If the audit sink fails, the authority returns an unavailable error and produces no attestation. A valid request is claimed in the replay ledger before authorization; therefore an audit outage after that claim intentionally requires a new, separately signed request rather than allowing retry ambiguity.

The attestation contains identifiers, policy and engine digests, issue/expiry times, a monotonic sequence, and outcome. It excludes raw mount paths, egress endpoints, signatures from the request, secrets, and all host-internal policy details.

## Key rotation and deployment

Trusted adapter keys and the engine signing key must be delivered from protected runtime configuration, never source control. Key rotation requires overlapping trusted public keys, signed release evidence, a staging exercise proving old-key rejection after expiry, and an audit record. A caller identity maps to one exact trusted key in this initial contract; replacing it requires an explicit configuration rollout.

## Operator verification

Run the standalone verifier from the repository root:

```bash
go run ./cmd/lifecycle-verify
```

Run the release gate before a merge or signed release:

```bash
bash ci/phase1-validate.sh
```

The expected output is `Phase 1 lifecycle and attestation validation passed.` This evidence proves only the contract authority. It is not authorization to activate Shared or Dedicated cages, admit tenants, or claim host isolation effectiveness.
