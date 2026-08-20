# Phase 4: Namespace, Mount, Process, Capability, Device, and Seccomp Plan

## Scope

Phase 4 defines the exact security plan that a later privileged executor must enforce atomically. It does not call `clone`, `unshare`, `setns`, `mount`, `pivot_root`, `execve`, `prctl`, `capset`, or seccomp syscalls. This separation prevents an unverified or partially constructed plan from becoming a host side effect.

The authority first calls the Phase 3 host preflight. It then validates the plan request and produces a canonical SHA-256 plan digest. Every decision, including every denial, is recorded before the result is returned. A future executor must validate the plan digest independently and reject a plan if any requested control is absent or differs from the signed authorization evidence.

## Required plan controls

| Boundary | Required state |
|---|---|
| Namespaces | Exactly one each of user, PID, mount, IPC, UTS, and network namespaces. |
| Identity maps | Exactly one non-root host UID map and one non-root host GID map; each maps container ID `0` for a single identity. |
| Process state | `no_new_privs`, empty capability bounding set, cleared environment, descriptors closed from FD 3, working directory `/`, parent-death `SIGKILL`, and a supervised PID-1 reaper. |
| Filesystem | Read-only base root with private propagation; restricted `/proc`; minimal `/dev`; bounded `tmpfs` `/tmp`; mandatory `nodev`, `nosuid`, and `noexec` flags. |
| Devices | Only `null`, `zero`, `random`, and `urandom`; no host device paths or device discovery. |
| Seccomp | A non-empty SHA-256 profile digest. Phase 7 must bind this digest to compiled profile bytes and inspect loaded filter evidence. |

## Explicit prohibitions

The plan validator rejects ambient capabilities, host UID/GID `0`, an omitted namespace, duplicate namespaces or mappings, inherited descriptors, inherited environment, non-root working directories, writable base roots, unfiltered `/proc`, expanded devices, unsafe `/tmp`, any protected Brick path, direct `/sys`, Docker or container-runtime sockets, and any mount not explicitly required by the contract.

The plan does **not** grant network access. The required private network namespace is only a topology boundary. Phase 5 supplies cgroup controls and default-deny network enforcement; a plan cannot be used as proof that egress is blocked.

## Operations

Keep the isolation plan authority and its audit sink inside the root-owned broker service domain. The policy source must provide fixed base-root and seccomp digests; it must never provide raw mount sources, device paths, capability sets, or syscall lists from a tenant-facing request. On a plan digest mismatch, audit failure, preflight failure, or malformed control, deny execution and preserve the protected audit event.

Before a real executor is enabled, perform an isolated staging escape test proving namespace invisibility, no inherited file descriptors, no inherited environment, no ambient capabilities, filtered `/proc`, inaccessible host devices, no protected mounts, and no surviving child after broker termination. The plan verifier below is not a substitute for that test.

## Verification

```bash
go run ./cmd/isolation-verify
bash ci/phase4-validate.sh
```

The verifier checks the versioned contract, creates a complete deterministic plan through the authority, and verifies the plan digest. Expected messages are `host-isolation plan verification passed` and `Phase 4 isolation-plan validation passed.`
