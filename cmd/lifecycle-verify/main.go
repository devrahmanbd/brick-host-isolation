package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/brick/host-isolation/lifecycle"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type audit struct{}

func (audit) RecordEvent(string, string, string, string, map[string]any) error { return nil }

type replay struct{ used bool }

func (r *replay) Claim(string, time.Time) (bool, error) {
	if r.used {
		return false, nil
	}
	r.used = true
	return true, nil
}

func main() {
	if err := verify(); err != nil {
		fmt.Fprintf(os.Stderr, "host-isolation lifecycle verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("host-isolation lifecycle verification passed")
}

func verify() error {
	contract, err := os.ReadFile("contracts/brick-host-isolation.v1.json")
	if err != nil {
		return fmt.Errorf("read contract: %w", err)
	}
	var parsed struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(contract, &parsed); err != nil || parsed.Schema != lifecycle.Schema {
		return fmt.Errorf("invalid contract schema")
	}
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	callerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	engineKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	authority, err := lifecycle.NewAuthority(engineKey, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]ed25519.PublicKey{"spiffe://brick/shared-adapter": callerKey.Public().(ed25519.PublicKey)}, audit{}, &replay{}, fixedClock{now})
	if err != nil {
		return err
	}
	req := lifecycle.Request{
		Schema: lifecycle.Schema, RequestID: "11111111-1111-4111-8111-111111111111", Action: lifecycle.ActionCreate, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute), CallerSPIFFEID: "spiffe://brick/shared-adapter", PolicyID: "policy-shared-tenant", PolicyDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Profile: lifecycle.ProfileSharedTenant, CageID: "cage-tenant-a", HostIdentity: "host-staging-a",
		ResourcePolicy: lifecycle.ResourcePolicy{CPUQuotaMilli: 500, MemoryMaxBytes: 1 << 30, PidsMax: 64, IOWeight: 100},
		MountPolicy:    lifecycle.MountPolicy{BaseRoot: "/srv/brick-cages/tenant-a", Mounts: []lifecycle.Mount{{Source: "/usr/bin", Destination: "/runtime/bin", ReadOnly: true}}, MandatoryLayers: []string{"auditBeforeResponse", "callerAuthentication", "capabilityDrop", "cgroupV2", "defaultDenyEgress", "environmentSanitization", "executableManifest", "immutableBaseRoot", "ipcNamespace", "mountNamespace", "networkNamespace", "noNewPrivileges", "pidNamespace", "protectedPathExclusion", "replayProtection", "seccomp", "userNamespace", "utsNamespace"}},
		NetworkPolicy:  lifecycle.NetworkPolicy{Mode: "defaultDeny", AllowedEndpoints: []string{"https://api.example.test"}}, ExecutableManifestDigest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", AuditTarget: "audit://host-isolation-ledger",
	}
	if err := lifecycle.SignRequest(&req, callerKey); err != nil {
		return err
	}
	attestation, err := authority.Authorize(req)
	if err != nil {
		return err
	}
	return lifecycle.VerifyAttestation(attestation, engineKey.Public().(ed25519.PublicKey), now)
}
