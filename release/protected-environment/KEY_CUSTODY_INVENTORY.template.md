# Brick Host Isolation — Production Key-Custody Inventory

> This template contains **non-secret operational metadata only**. Do not place private keys, seed material, recovery codes, client certificates, or credential exports in this repository, CI logs, ticketing systems, or general-purpose chat.

| Key role | Required separate custody boundary | Permitted signing inputs | Non-secret key/KMS reference | Primary custodian | Recovery approvers | Rotation interval | Last verified | Status |
|---|---|---|---|---|---|---|---|---|
| Artifact manifest | Dedicated release-signing service or HSM/KMS policy | Ordered release artifact manifest only | `REPLACE` | `REPLACE` | `REPLACE_TWO_OR_MORE_APPROVERS` | `REPLACE` | `REPLACE_RFC3339_UTC` | `PENDING` |
| Benchmark evidence | Separate performance-evidence signing policy | Benchmark evidence only | `REPLACE` | `REPLACE` | `REPLACE_TWO_OR_MORE_APPROVERS` | `REPLACE` | `REPLACE_RFC3339_UTC` | `PENDING` |
| Security review | Independent security-review signing policy | Approved scoped review only | `REPLACE` | `REPLACE_SECURITY_TEAM` | `REPLACE_TWO_OR_MORE_APPROVERS` | `REPLACE` | `REPLACE_RFC3339_UTC` | `PENDING` |
| Phase 8 staging evidence | Protected staging-evidence signing service | Shared/Dedicated Phase 8 evidence only | `REPLACE` | `REPLACE` | `REPLACE_TWO_OR_MORE_APPROVERS` | `REPLACE` | `REPLACE_RFC3339_UTC` | `PENDING` |
| Core policy gate | Core-only admission signing policy | Core admission/certification/GA records only | `REPLACE` | `REPLACE_CORE_OWNER` | `REPLACE_TWO_OR_MORE_APPROVERS` | `REPLACE` | `REPLACE_RFC3339_UTC` | `PENDING` |
| Guarded-release certificate | Certificate-only release authority policy | Phase 9 certificate payload only | `REPLACE` | `REPLACE_RELEASE_AUTHORITY_OWNER` | `REPLACE_TWO_OR_MORE_APPROVERS` | `REPLACE` | `REPLACE_RFC3339_UTC` | `PENDING` |

## Mandatory custody assertions

Each row must be independently verified before `PENDING` changes to `VERIFIED`. A private key must be non-exportable or protected by a documented exception approved by security; must be inaccessible to tenant, build, edition, and review workloads; and must have an auditable signing policy constrained to the permitted input type. No person, workload identity, service account, or recovery procedure may have routine authority to use more than one of the six signing roles.

Record only stable key identifiers, key policy revisions, approval references, and verification timestamps here. Store sensitive key escrow and identity-enrollment material in the designated protected secrets system, not in this file.
