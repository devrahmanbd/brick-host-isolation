package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/brick/host-isolation/integrity"
	"github.com/brick/host-isolation/lifecycle"
	"github.com/brick/host-isolation/resource"
)

type resourceVerifier struct{}

func (resourceVerifier) VerifyPlan(resource.Plan) error { return nil }

type audit struct{}

func (audit) RecordEvent(string, string, string, string, map[string]any) error { return nil }

type inspector map[string]integrity.FileIdentity

func (i inspector) Inspect(path string) (integrity.FileIdentity, error) {
	value, ok := i[path]
	if !ok {
		return integrity.FileIdentity{}, errors.New("not found")
	}
	return value, nil
}

func main() {
	if err := verify(); err != nil {
		fmt.Fprintf(os.Stderr, "host-isolation integrity verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("host-isolation integrity verification passed")
}

func verify() error {
	data, err := os.ReadFile("contracts/brick-host-isolation-integrity.v1.json")
	if err != nil {
		return err
	}
	var contract struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &contract); err != nil || contract.Schema != integrity.Schema {
		return fmt.Errorf("invalid integrity contract")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	manifest := integrity.Manifest{Schema: integrity.Schema, ManifestID: "manifest-verify-v1", Profile: lifecycle.ProfileSharedTenant, Entries: []integrity.Entry{{Path: "/runtime/bin/httpd", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", OwnerUID: 0, Mode: 0o755, Arguments: []string{"--foreground", "--port=8080"}, Environment: []integrity.Environment{{Name: "HOME", Value: "/nonexistent"}, {Name: "LANG", Value: "C.UTF-8"}, {Name: "TMPDIR", Value: "/tmp"}, {Name: "TZ", Value: "UTC"}}, Interpreter: &integrity.Dependency{Path: "/runtime/interpreters/loader", Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", OwnerUID: 0, Mode: 0o755}, RuntimeDependencies: []integrity.Dependency{{Path: "/runtime/lib/libbrick.so", Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", OwnerUID: 0, Mode: 0o644}}}}}
	if err := integrity.SignManifest(&manifest, key); err != nil {
		return err
	}
	files := inspector{"/runtime/bin/httpd": {Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", OwnerUID: 0, Mode: 0o755, Regular: true}, "/runtime/interpreters/loader": {Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", OwnerUID: 0, Mode: 0o755, Regular: true}, "/runtime/lib/libbrick.so": {Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", OwnerUID: 0, Mode: 0o644, Regular: true}}
	authority, err := integrity.NewAuthority(manifest, key.Public().(ed25519.PublicKey), resourceVerifier{}, files, audit{})
	if err != nil {
		return err
	}
	resourcePlan := resource.Plan{Schema: resource.Schema, CageID: "cage-verify-a", Profile: lifecycle.ProfileSharedTenant, PlanDigest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
	request := integrity.Request{Schema: integrity.Schema, CageID: "cage-verify-a", Profile: lifecycle.ProfileSharedTenant, ResourcePlanDigest: resourcePlan.PlanDigest, ExecutablePath: "/runtime/bin/httpd", Arguments: []string{"--foreground", "--port=8080"}}
	plan, err := authority.Prepare(context.Background(), "spiffe://brick/verify", resourcePlan, request)
	if err != nil {
		return err
	}
	return authority.VerifyPlan(plan)
}
