# Phase 7: Signed Audit, Attestation, Freeze, and Recovery

## Scope

Phase 7 introduces the recovery-control authority for an anomalous cage. It generates signed, append-oriented redacted events and a signed completion attestation. The authority controls the required ordering only; it does not directly signal a process, freeze a cgroup, remove a route, collect host data, destroy a filesystem, or rebuild a cage. Those privileged operations remain behind narrow broker-owned interfaces for a later root-owned executor.

## Mandatory recovery order

| Sequence | Operation | Safety purpose |
|---:|---|---|
| 1 | Record request | Requires a signed journal and audit event before any side effect. |
| 2 | Kill | Stops the workload before attempting any evidence collection or cleanup. |
| 3 | Freeze | Prevents remaining cgroup tasks from resuming after kill handling. |
| 4 | Withdraw network | Removes the cage egress path before evidence capture. |
| 5 | Capture evidence | Stores a referenced evidence digest, not host paths, commands, output, secrets, or customer payload. |
| 6 | Destroy | Delegates secure cage destruction only after evidence capture. |
| 7 | Clean-rebuild handoff | Transfers the cage identity and evidence digest to a future rebuild workflow. |
| 8 | Sign completion | Produces signed final evidence only after all preceding operations have succeeded. |

Every event includes the policy digest, cage ID, caller SPIFFE identity, host identity, monotonic sequence, outcome, redacted reason code, timestamp, optional evidence digest, and Ed25519 signature. The contract intentionally forbids host paths, commands, arguments, environments, secrets, raw policy values, and customer payload from event material.

## Failure behavior

The journal and audit event are prerequisites for the first side effect. If either is unavailable, the authority returns unavailable and does not invoke the cage controller. After recovery starts, an error or cancellation prevents every later step. A failed step is itself signed, journaled, and audited where those dependencies remain available. A recovery completion attestation is never issued after a failed operation.

The controller implementation must accept only a validated cage ID and operate within the fixed broker-owned cgroup, network, and filesystem subtrees. It must not concatenate policy-supplied paths, shell fragments, environment values, or command strings. Evidence capture must persist redacted evidence under controlled storage before returning its SHA-256 digest. A future destroyer must keep evidence immutable and preserve the event journal for incident investigation.

## Operations

Treat a recovery as a security incident. Preserve the journal, audit trail, signed attestation if produced, release digest, Phase 4 plan digest, Phase 5 resource plan, Phase 6 execution plan, and evidence object. Do not retry clean rebuild after a failed destroy or evidence capture without human review. Do not remove or rewrite a replay/event ledger to resume admission.

Before operational activation, test: a live anomalous cage, non-responsive PID 1, repeated child processes, cgroup freeze failure, egress-withdrawal failure, evidence-store outage, journal outage, audit outage, destroy failure, rebuild-handoff failure, and restart during every recovery sequence. The Phase 7 verifier does not exercise privileged host effects.

## Verification

```bash
go run ./cmd/recovery-verify
bash ci/phase7-validate.sh
```

The verifier validates the versioned contract, performs a deterministic recovery using injected safe interfaces, checks the exact kill-first controller order, verifies each signed event, and verifies the final attestation. Expected output ends with `host-isolation recovery verification passed` and `Phase 7 recovery validation passed.`
