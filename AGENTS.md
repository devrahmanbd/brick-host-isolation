# Brick Host Isolation Development Governance

## Repository purpose and hard boundary

This private repository owns only the reusable Linux host-isolation runtime. It may contain a root-owned broker, an unprivileged helper, policy and attestation types, platform checks, cgroup v2 management, namespace/mount/network setup, seccomp profiles, executable-manifest verification, audit export, and a staging escape-test suite.

It **must not** contain Brick panel UI, API routing, database models, billing, tenant business workflows, customer records, Core authorities, or any Brick control-plane source/binary that could be exposed to a workload. `core` must not import or execute this implementation. It only verifies its signed evidence.

## Non-negotiable security rules

1. Deny by default. Missing configuration, unavailable audit storage, unavailable trusted keys, stale evidence, malformed policies, or ambiguous identity must fail closed.
2. Do not interpolate policy-derived values into shells. Prefer typed system calls or `execve` with fixed executable paths and explicit argument vectors. Any unavoidable shell boundary requires a separately reviewed quoting helper and a focused injection test.
3. Never use permissive SSH host-key callbacks, privileged customer execution, host networking, writable protected mounts, inherited environment variables, inherited file descriptors, or ambient Linux capabilities.
4. Do not mount `/opt/brick`, `/var/lib/brick`, `/run/brick`, Brick source directories, control-plane sockets, secrets, signing keys, package caches, Docker sockets, container runtime sockets, or host device nodes into a customer cage.
5. Every signed request requires caller workload identity, policy digest, request identifier, issuance/expiry window, and durable single-use replay protection. Every outcome must be audit-recorded before it is returned.
6. Cgroup limits, seccomp profiles, mounts, network policy, and executable manifest are all mandatory layers. A profile that omits any mandatory layer is invalid rather than partially applied.
7. Customer-visible errors are stable and non-sensitive. Detailed host paths, policy material, secret values, and implementation internals belong only in the protected audit path.

## Branch and release discipline

`main` is protected and release-oriented. Work occurs on focused branches and reaches `main` only after formatting, deterministic tests, race detection, static analysis, the staging escape suite, an SBOM, vulnerability review, and security review. Never force-push a release tag.

Shared and Dedicated consume signed, immutable releases. Do not copy engine code into either edition, and do not merge an edition branch into this repository or into Core. Edition adapters are compatibility clients, not runtime forks.

## Required artifact pattern

Every implementation phase must include a versioned contract, fail-closed authority or lifecycle implementation, deterministic adversarial tests, a standalone verifier, a CI gate, an operational runbook, and release evidence. Keep public identifiers and JSON fields camelCase. New security-sensitive code requires negative tests for malformed input, replay, stale signature, audit failure, path escape, process escape, egress bypass, and resource exhaustion where applicable.
