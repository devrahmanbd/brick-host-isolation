# Phase 3: Linux Host Preflight and Immutable Base Root

## Scope

Phase 3 supplies the broker-compatible host-preflight authority and the preparation authority for a future overlay-style cage filesystem. The preflight authority is evaluated at authorization time; it deliberately has no positive-result cache. The base-root authority validates an existing immutable tree and creates only empty, owner-controlled `upper` and `work` directories for a cage. It never mounts an overlay, enters namespaces, activates a cage, or starts a workload.

## Admission conditions

| Area | Fail-closed requirement |
|---|---|
| Platform and kernel | Linux with a configured minimum kernel version. |
| Confinement features | Non-empty cgroup v2 controller file, positive user namespace limit, and the `filter` seccomp action. |
| LSM posture | Required LSM listed and actively enforcing. AppArmor requires `Y`; SELinux requires `1`. |
| Mount posture | Every protected or base-root path resolves to a private mount; shared, slave, and unbindable propagation are rejected. |
| Managed paths | Required paths are direct, owner-controlled directories or explicitly configured regular service files, with no symlink and no group/world write permission. |
| Base root | Exact expected owner and mode, allowed filesystem type, private mount propagation, no symlinks, devices, setuid/setgid files, group/world-writable entries, or unexpected ownership. |

## Production configuration

Production must pass `LinuxProbe` with root ownership expectations, use root-owned `0755` or stricter base-root directory mode, and use a root-owned `0700` ephemeral parent on a locally durable allowed filesystem. The caller must provide an explicit filesystem allowlist matching the provisioned volume. Do not permit network, FUSE, or shared host-path filesystems merely to make configuration convenient.

The broker uses this preflight through its `HostPreflight` interface. Configure the broker with one `Preflight` instance that names the deployed protected paths, readiness-file sources, base root, required LSM, and minimum kernel. Any preflight error must remain an unavailable lifecycle outcome; it must never be suppressed or replaced with a stale successful result.

## Operations and incident response

An LSM, cgroup, kernel, mount-propagation, ownership, readiness, clock, or immutable-tree failure blocks new authorization decisions. Preserve audit and ledger records, repair the host through reviewed configuration management, rerun the verifier and release gate, then perform an independent staging drill. Do not make a protected directory writable, relax the LSM posture, or remove a problematic base-root entry in place as an emergency workaround.

The ephemeral layer pair is intentionally not a mounted filesystem. Its existence is evidence only that the immutable-root and local directory checks passed at creation time. It does not prove namespace, mount, capability, cgroup, seccomp-filter, or network enforcement; those controls remain later phases.

## Verification

```bash
go run ./cmd/host-verify
bash ci/phase3-validate.sh
```

The standalone verifier validates the versioned contract, evaluates a deterministic compliant host snapshot, scans a local owner-controlled base-root fixture, and creates an ephemeral upper/work pair. The expected final messages are `host-isolation host verification passed` and `Phase 3 host-preflight and base-root validation passed.`
