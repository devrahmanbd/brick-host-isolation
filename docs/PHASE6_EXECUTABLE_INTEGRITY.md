# Phase 6: Executable and Environment Integrity

## Scope

Phase 6 creates the authorization boundary for a future `execve` executor. A root-owned release process supplies an Ed25519-signed manifest containing every approved executable, interpreter, and runtime dependency. Each identity is pinned to an absolute path, SHA-256 digest, root ownership, exact mode, fixed argument vector, and minimal canonical environment.

The authority first verifies a previously validated Phase 5 resource-plan digest, then refuses any request that tries to select a program, argument, environment item, dependency, loader, interpreter, or path outside the signed manifest. It queries an injected file inspector before issuing an execution plan. This keeps filesystem opening and privileged execution outside the authority and makes the future executor independently responsible for safe `openat2`/file-descriptor-based identity checking.

## Required manifest and execution posture

| Area | Required control |
|---|---|
| Signer | One configured Ed25519 public key; unsigned, malformed, or modified manifests are unavailable. |
| Executable | Root-owned `0755` regular file under `/runtime/bin/` or `/runtime/interpreters/`; no `PATH` lookup and no symlinks. |
| Interpreter and libraries | Exact root-owned regular files under the runtime paths, each with a pinned SHA-256 digest and mode. |
| Arguments | Fixed vector supplied by the signed manifest; tenant input cannot add, remove, or change an argument. |
| Environment | Only `HOME=/nonexistent`, `TMPDIR=/tmp`, `LANG=C` or `C.UTF-8`, and `TZ=UTC` are representable. |
| Injection removal | `PATH`, dynamic-loader variables, language preloads, plugin hooks, shell startup variables, `GODEBUG`, `IFS`, `CDPATH`, and all unlisted environment names are forbidden. |
| Process handoff | The plan mandates root working directory, no path lookup, and closing descriptors from FD 3. |

## Operational requirements

The manifest signer must be stored outside the runtime host and released through the protected deployment pipeline. Signing keys, private package repositories, source trees, package-manager caches, user home directories, dynamic linker configuration, and plugin directories must be absent from cage visibility. A manifest update requires a signed release digest, two-party review, staging inspection, independent verification against the immutable base root, and a rollback manifest.

The injected inspector is not permitted to follow symlinks or accept device, directory, non-regular, non-root-owned, or mode-drifted files. The Phase 6 authority validates the inspector result but does not prevent a time-of-check/time-of-use race on its own. The later executor must re-open approved files without path traversal, compare the open file identity to the signed manifest, clear the real process environment, set the working directory, close descriptors, and execute only the opened identity.

## Incident response and verification

Any manifest-signature failure, unexpected runtime file, digest drift, root ownership drift, mode drift, interpreter/dependency mismatch, dynamic-loader exposure, or audit failure blocks workload admission. Preserve the manifest, release evidence, inspector result, resource plan, and audit entries; do not waive a digest mismatch to restore service.

```bash
go run ./cmd/integrity-verify
bash ci/phase6-validate.sh
```

The verifier validates the versioned contract, signs and verifies a deterministic manifest, binds it to a resource plan, checks executable/interpreter/dependency identities, generates a canonical execution plan, and verifies its digest. It does not execute an untrusted program or inspect a production root filesystem.
