# Security Policy

## Scope

Report vulnerabilities in the broker, request verification, host preflight, namespace/mount/cgroup/network/seccomp enforcement, executable verification, audit/attestation integrity, release process, or staging test harness. Do not file public issue reports for unpatched escape or privilege-escalation findings.

## Reporting and handling

Report privately to the Brick security owner with the affected release digest, operating system and kernel version, profile, reproducible steps, expected boundary, observed behavior, and any safe proof. Do not include customer data, secrets, private keys, or public exploit payloads.

The response process must acknowledge receipt, validate reproducibility in an isolated environment, issue a severity decision, create a remediation and release plan, prepare revocation/rollback guidance where needed, and document the final evidence in the protected security record.

## Release blocking

Any unresolved escape, host-path exposure, replay, signature bypass, privilege escalation, audit bypass, protected-asset mount, cross-cage leak, or default-deny network bypass blocks release. A temporary mitigation is not a release authorization unless it is independently reviewed, time-bound, auditable, and incorporated into the certification evidence.
