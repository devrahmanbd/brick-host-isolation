# Brick Host Isolation Release Candidate — v1.0.0

## Candidate identity

| Field | Recorded value |
|---|---|
| Candidate release identifier | `v1.0.0` |
| Repository | `github.com/brick/host-isolation` |
| Source branch | `main` |
| Immutable source commit | `b2ff94d6f8496bd9f14fe55cff651422b953d31c` |
| Parent commit | `ad1602f60e49e0369ce617925c841db1d7dc90f9` |
| Commit author timestamp | `2026-08-20T04:11:19Z` |
| Commit subject | `feat(certification): add phase 9 guarded release authority` |
| Local/remote verification | Local `HEAD` and `origin/main` both resolved to the source commit above before this record was created. |

## Candidate scope

This candidate contains Brick Host Isolation Phases 1 through 9, including the Phase 9 certification and guarded-release authority. It is the input candidate for the protected real-candidate ceremony; it does not authorize an edition to pin, deploy, or admit a tenant workload.

> **Status: candidate selected; release not certified.** This record is a source-control selection record only. It is not a Git tag, signed artifact manifest, SBOM, benchmark record, independent security review, staging-evidence record, Core policy gate, guarded-release certificate, or production approval.

## Required next evidence

The selected source commit is eligible to enter, but has not completed, the Phase 9 protected release ceremony. Before Shared or Dedicated may pin `v1.0.0`, retain a complete, matching, and independently signed evidence bundle for this exact full source commit:

1. Actual CycloneDX SBOM and signed artifact manifest.
2. Signed reproducible benchmark evidence.
3. Signed approved independent security review.
4. Signed Phase 8 staging evidence from isolated Shared and Dedicated hosts.
5. Six signed, current Core records: admission, certification, and GA for each edition.
6. A valid Phase 9 Ed25519 guarded-release certificate and protected audit correlation.

Any evidence referring to another release identifier or commit is invalid for this candidate. The release ceremony must execute in the protected release environment with separate signer custody as defined in `docs/PHASE9_CERTIFICATION_GUARDED_RELEASE.md`.
