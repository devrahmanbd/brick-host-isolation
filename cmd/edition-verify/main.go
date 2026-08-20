package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/brick/host-isolation/edition"
	"github.com/brick/host-isolation/lifecycle"
	"github.com/brick/host-isolation/resource"
)

type resourceVerifier struct{}

func (resourceVerifier) VerifyPlan(resource.Plan) error { return nil }

type audit struct{}

func (audit) RecordEvent(string, string, string, string, map[string]any) error { return nil }

type runner struct{}

func (runner) Run(_ context.Context, scenario edition.Scenario, _ edition.Compilation) (edition.Observation, error) {
	return edition.Observation{Scenario: scenario, Passed: true, EvidenceDigest: strings.Repeat("a", 64)}, nil
}

func main() {
	if err := verify(); err != nil {
		fmt.Fprintf(os.Stderr, "host-isolation edition verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("host-isolation edition verification passed")
}

func verify() error {
	data, err := os.ReadFile("contracts/brick-host-isolation-edition.v1.json")
	if err != nil {
		return err
	}
	var contract struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &contract); err != nil || contract.Schema != edition.Schema {
		return fmt.Errorf("invalid edition contract")
	}
	releaseBinding, err := loadReleaseBinding()
	if err != nil {
		return err
	}
	template := func(profile lifecycle.Profile, executable string) edition.Template {
		return edition.Template{
			Profile: profile,
			Limits: resource.Limits{
				CPUQuotaMicros:    50000,
				CPUPeriodMicros:   100000,
				MemoryMaxBytes:    1 << 30,
				PidsMax:           64,
				FileDescriptorMax: 512,
				WallClockSeconds:  600,
			},
			Network:        resource.NetworkPolicy{Mode: "denyAll"},
			ExecutablePath: executable,
			Arguments:      []string{"--foreground"},
		}
	}
	compiler, err := edition.NewCompiler(map[edition.Edition]edition.Template{
		edition.Shared:    template(lifecycle.ProfileSharedTenant, "/runtime/bin/shared-entry"),
		edition.Dedicated: template(lifecycle.ProfileDedicatedAdministrator, "/runtime/bin/dedicated-entry"),
	}, resourceVerifier{}, audit{})
	if err != nil {
		return err
	}
	compilation, err := compiler.Compile(context.Background(), "spiffe://brick/verify", edition.Intent{
		Schema:         edition.Schema,
		Edition:        edition.Shared,
		CageID:         "cage-verify-a",
		BaseRootDigest: strings.Repeat("b", 64),
		SeccompDigest:  strings.Repeat("c", 64),
	})
	if err != nil {
		return err
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	staging, err := edition.NewStagingAuthority(key, runner{}, audit{}, func() time.Time {
		return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	})
	if err != nil {
		return err
	}
	evidence, err := staging.Run(context.Background(), "spiffe://brick/verify", "11111111-1111-4111-8111-111111111111", compilation, releaseBinding)
	if err != nil {
		return err
	}
	return edition.VerifyEvidence(evidence, key.Public().(ed25519.PublicKey))
}

func loadReleaseBinding() (edition.ReleaseEvidenceBinding, error) {
	paths := []string{}
	if path := os.Getenv("BRICK_RELEASE_EVIDENCE_BINDING_FIXTURE"); path != "" {
		paths = append(paths, path)
	}
	paths = append(paths,
		"contracts/fixtures/release-evidence-binding.v1.valid.json",
		"../contracts/fixtures/release-evidence-binding.v1.valid.json",
	)
	var last error
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			last = err
			continue
		}
		return edition.LoadReleaseEvidenceBinding(raw)
	}
	return edition.ReleaseEvidenceBinding{}, last
}
