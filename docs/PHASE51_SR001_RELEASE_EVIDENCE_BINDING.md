# Phase 51 — SR-001 Release-Evidence Binding Enforcement

## Enforcement Boundary

Phase 8 staging evidence now contains a strict `brick.release-evidence-binding.v1` value. It is included in the canonical signed evidence payload. Phase 8 rejects missing, malformed, unknown-version, or non-canonical release bindings before it emits evidence.

Phase 9 derives the expected binding from the submitted release ID, full source commit, signed artifact-manifest digest, and manifest SBOM digest. It rejects each Shared and Dedicated evidence record unless every binding field is exactly equal to that derived value. A valid staging signature does not override a mismatch.

| Rejected condition | Enforcing phase |
|---|---|
| Missing release binding or required field | Phase 8 evidence verifier |
| Wrong release or commit | Phase 8 verifier and Phase 9 exact comparison |
| Malformed/short digest or commit | Phase 8 verifier |
| Wrong manifest or SBOM digest | Phase 9 exact comparison |
| Staging record reused for another candidate | Phase 9 exact comparison |

## Operator Procedure

The Phase 8 runner receives a binding copied from the immutable release candidate and signs it with every observation. The Phase 9 submitter supplies the original signed artifact manifest, not a digest supplied by a caller. Certification derives the expected binding itself and fails closed if either edition’s evidence differs.

The local reciprocal gate requires `BRICK_CORE_DIR` to reference an independently checked-out Core source tree. It compares the shared contract byte-for-byte, exercises this repository’s Phase 8 verifier with Core’s fixture, exercises Core’s verifier with this repository’s fixture, and runs Phase 8/9 race tests.

## GitHub Actions Prerequisite

The host-isolation repository requires `BRICK_CORE_READ_TOKEN`: a distinct least-privilege, read-only credential for `devrahmanbd/flamehoster` on the `core` branch. Missing access fails the gate intentionally. It must never be a signing, deployment, or customer-service credential.

## Recovery Rule

Do not edit signed staging evidence to repair a mismatch. Preserve the rejected record, determine whether the release inputs or evidence selection were wrong, create a fresh binding from the selected immutable candidate, rerun the required stage, and obtain new signed evidence. The recovery action remains outside this authority; it cannot waive the mismatch.
