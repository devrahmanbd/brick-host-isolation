# Brick Host Isolation — Protected Release Environment Acceptance

**Candidate:** `v1.0.0` at `b2ff94d6f8496bd9f14fe55cff651422b953d31c`  
**Environment identifier:** `REPLACE`  
**Assessment timestamp (UTC):** `REPLACE_RFC3339_UTC`  
**Assessor:** `REPLACE_SPIFFE_ID_OR_APPROVED_OPERATOR_ID`

| Control | Required production assertion | Evidence reference only | Result |
|---|---|---|---|
| Host boundary | Release host is persistent, patched, access-controlled, and separate from tenant/cage hosts and build workers. | `REPLACE_PROTECTED_EVIDENCE_REFERENCE` | `PENDING` |
| Trust bundle | Public-key-only bundle parses, declares the exact candidate ID/SHA, has six distinct 32-byte Ed25519 public keys, and has bounded 1-hour certificate/24-hour evidence lifetimes. | `REPLACE_PROTECTED_EVIDENCE_REFERENCE` | `PENDING` |
| Key custody | All six role rows in the custody inventory are independently verified; no private key is present in source control, host filesystem, CI configuration, or routine operator environment. | `REPLACE_PROTECTED_EVIDENCE_REFERENCE` | `PENDING` |
| Broker health | Root-owned Unix socket directory and socket pass ownership/mode checks; TLS 1.3 mutual authentication, exact SPIFFE allowlist, peer-UID allowlist, rate limiting, preflight dependency, and mandatory audit sink are active. | `REPLACE_PROTECTED_EVIDENCE_REFERENCE` | `PENDING` |
| Authorization health | An authorized synthetic request succeeds only with an approved test identity and complete signed fixture evidence; an unauthorized UID, SPIFFE identity, malformed frame, and over-rate request are denied and audit-recorded. | `REPLACE_PROTECTED_EVIDENCE_REFERENCE` | `PENDING` |
| Audit write | A synthetic pre-authorized health event receives a durable append-only audit sequence/reference; a read-back verifies actor, action, outcome, candidate linkage, timestamp, and integrity protection. | `REPLACE_PROTECTED_EVIDENCE_REFERENCE` | `PENDING` |
| Audit failure | With audit write disabled or unavailable, the broker and Phase 9 authority fail closed and return no authorization or certificate. | `REPLACE_PROTECTED_EVIDENCE_REFERENCE` | `PENDING` |
| Evidence store | Store enforces write-once retention, restricted writer/reader roles, integrity verification, encrypted backup, retention hold, and tested restoration without overwrite. | `REPLACE_PROTECTED_EVIDENCE_REFERENCE` | `PENDING` |
| Time and revocation | Trusted UTC source, signer revocation distribution, review expiry handling, and certificate expiry checks have been exercised. | `REPLACE_PROTECTED_EVIDENCE_REFERENCE` | `PENDING` |

> **Approval condition:** Every row must be `PASS`, its evidence reference must resolve in the protected evidence store, and an independent security approver must sign the acceptance outside this repository. A partially completed acceptance record must not be used as a release approval.
