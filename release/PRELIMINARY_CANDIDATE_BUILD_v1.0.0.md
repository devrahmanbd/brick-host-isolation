# Preliminary Candidate Build Transcript — v1.0.0

## Status and boundary

This is an **unsigned preliminary build transcript** for the selected candidate `v1.0.0` at `b2ff94d6f8496bd9f14fe55cff651422b953d31c`. It records the result of building a clean detached worktree at that exact commit. It is not protected-store evidence, a signed artifact manifest, a release certificate, a Git tag, or authority for Shared or Dedicated to pin a release.

The actual binary artifacts, source archive, CycloneDX SBOM, checksums, and pre-signing manifest are held only in the local release-artifact staging area pending transfer to the protected evidence store. They are deliberately not committed to this source repository.

## Reproducibility inputs

| Input | Recorded value |
|---|---|
| Candidate release ID | `v1.0.0` |
| Source commit | `b2ff94d6f8496bd9f14fe55cff651422b953d31c` |
| Source tree object | `1b8dc89b5cd6b3197065d5894f0a893830b32447` |
| Source commit timestamp | `2026-08-20T04:11:19Z` |
| Source date epoch | `1787199079` |
| Build target | Linux/amd64, `CGO_ENABLED=0` |
| Go build controls | `-trimpath -buildvcs=false -ldflags='-s -w'` |
| SBOM format | CycloneDX JSON 1.5 |
| SBOM generator | `cyclonedx-gomod v1.8.0` |

The source archive was produced by `git archive` from the selected commit with deterministic gzip output. Each verifier was built from the same clean detached worktree. The generator-produced Go-module inventory was bound to the selected candidate version `v1.0.0`; its dependency inventory was not manually modified.

## Candidate artifact digest set

| Ordered path | SHA-256 | Size (bytes) |
|---|---|---:|
| `bin/broker-verify` | `ec74996be7eaa0fa0285d9f12d04738a421ef59786dfd479fb3a2a3ed12e675a` | 4,493,464 |
| `bin/certification-verify` | `eb90338039c3e505b5c16eb1bf8c028f00ba6b2315d22e4f7e9b8a3f6792cb99` | 2,097,304 |
| `bin/edition-verify` | `643da4a1fb7c304635873aac9afadf9478355bdc922baf3aec478ece45e827a1` | 2,199,704 |
| `bin/host-verify` | `4526e324a9a7709c30044ac82a12acfc1cc5469077330ee964203a649f002724` | 1,863,832 |
| `bin/integrity-verify` | `9d00f3958f2db1c4c11761c7a55943a13ad14124b06ac83b53f3a6974f3cc6e8` | 2,203,800 |
| `bin/isolation-verify` | `af026f61ead5db4bc0a476e18a07d7acf11ed94604cfdc97641ef4e7dd4cb0c7` | 2,150,552 |
| `bin/lifecycle-verify` | `b1d7eb11936e7a5630a1a0681c5dffe8c66f956ecccf3a512909390a810d1cc3` | 2,203,800 |
| `bin/recovery-verify` | `dadd78f95187b9454b3a41cf9939eba852738856a1dcc595b543eef83966105d` | 2,162,840 |
| `bin/resource-verify` | `ffc867fca3f7fab90b6b8cda2dfbc9a0d7f76654164968ad3d2f84f503ab0b79` | 2,183,320 |
| `sbom/brick-host-isolation-v1.0.0.cdx.json` | `fa44c6748b9c906454578f9354217527b9da6d79e9ce1bb964f43b9e2e38c1df` | 1,937 |
| `source/brick-host-isolation-v1.0.0-src.tar.gz` | `904313774fe96f8f9c507884589c5105c76b4063a4d1b0f4b939b115725f820f` | 83,355 |

The SBOM SHA-256 is **`fa44c6748b9c906454578f9354217527b9da6d79e9ce1bb964f43b9e2e38c1df`**. The ordered eleven-entry pre-signing manifest SHA-256 is **`8e94860f67a5cb14e2e9b86ef94a0c40c72ca43e0b4ef7af196d1e23b011106e`**.

## Verification and remaining hold

The local candidate verifier checked every manifest path for sorting and traversal safety; each file’s SHA-256 digest and exact size; the SBOM digest binding; manifest candidate ID/commit binding; explicit `PENDING_PROTECTED_ARTIFACT_SIGNER` status; and CycloneDX name, version, format, and specification version. The complete checksum inventory also verified successfully.

> **Artifact-signing hold:** The staged pre-signing manifest is not the Phase 9 `brick.host-isolation.artifact-manifest.v1` record. Submit it, its SBOM, and the exact artifact bytes to the separately controlled artifact-manifest Ed25519 signer in the protected release environment. Retain the valid signed manifest there, then verify it with the public artifact-signing key before continuing the ceremony.
