# Phase 5: Cgroup v2 Resource Controls and Default-Deny Egress

## Scope

Phase 5 constructs the resource and egress plan that a later root-owned executor must apply before a workload is started. It authorizes a single child cgroup beneath the fixed broker-owned subtree `/sys/fs/cgroup/brick-isolation/<cage-id>` and writes the complete controller sequence: `cpu.max`, `memory.max`, `memory.high`, `memory.swap.max`, `pids.max`, and `io.max`. File-descriptor and wall-clock limits are executor-bound values because they are not cgroup v2 controller files.

The authority has no host-cgroup fallback and no unlimited value. It validates a previously verified Phase 4 plan digest and requires that plan to have a private network namespace, `no_new_privs`, cleared environment, and descriptor close boundary. Any mismatched plan, missing limit, unknown cgroup root, incomplete controller sequence, failed audit event, cancellation, or controller write failure blocks workload admission.

## Resource policy

| Resource | Required control |
|---|---|
| CPU | Positive quota within a fixed `100000` microsecond period; no unlimited quota. |
| Memory and swap | Positive `memory.max`, positive `memory.high` not above max, and explicit swap maximum. |
| Process count | Positive `pids.max`; PID limit is never delegated to a tenant-facing runtime. |
| I/O | Non-empty, unique major:minor device rules with positive BPS and IOPS ceilings. |
| File descriptors | Positive executor-enforced ceiling. |
| Runtime duration | Positive executor-enforced wall-clock deadline. |

The cgroup adapter is intentionally a narrow injected interface. A production adapter must be root-owned, operate only under the fixed broker subtree, use no symlink traversal, verify controller availability before writes, and preserve evidence if cleanup cannot remove a partially configured cgroup. The Phase 5 authority attempts cleanup after any incomplete write sequence but does not treat cleanup success as proof that the host is safe.

## Default-deny network policy

`denyAll` is the default and accepts no proxy identity or endpoints. A `proxyOnly` plan can be issued only for a non-empty exact SPIFFE proxy identity and an explicit, deduplicated set of lowercase HTTPS server names on port 443. It is a declaration of intended egress, not a direct network permission.

The later network executor must create a private namespace with no direct host route, attach only the broker-approved proxy path, verify the proxy identity, enforce destination and TLS policy, deny raw sockets and DNS bypass, and record connection decisions. Any unavailable proxy, unresolved proxy identity, policy mismatch, route creation failure, or firewall error must leave the namespace without egress.

## Operations and verification

Do not create cgroups beneath system or user subtrees, do not use `max` for a tenant policy, and do not permit direct veth, bridge, host, or container-runtime network attachment. Treat `memory.events`, `pids.events`, `io.stat`, cgroup pressure files, executor FD failures, deadline expirations, and proxy denials as security and capacity telemetry after later observability phases are available.

```bash
go run ./cmd/resource-verify
bash ci/phase5-validate.sh
```

The standalone verifier validates the contract, derives a verified Phase 4 plan, constructs a bounded deny-all resource plan, verifies its digest, and exercises all six cgroup writes through the narrow adapter. It does not configure a real cgroup or network namespace.
