package edition

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/brick/host-isolation/isolation"
	"github.com/brick/host-isolation/lifecycle"
	"github.com/brick/host-isolation/resource"
)

type audit struct {
	fail   bool
	events int
}

func (a *audit) RecordEvent(string, string, string, string, map[string]any) error {
	a.events++
	if a.fail {
		return errors.New("audit unavailable")
	}
	return nil
}

type resourceVerifier struct{ fail bool }

func (v resourceVerifier) VerifyPlan(resource.Plan) error {
	if v.fail {
		return errors.New("resource plan invalid")
	}
	return nil
}

type runner struct {
	fail  Scenario
	calls []Scenario
}

func (r *runner) Run(_ context.Context, s Scenario, _ Compilation) (Observation, error) {
	r.calls = append(r.calls, s)
	if r.fail == s {
		return Observation{}, errors.New("scenario failed")
	}
	return Observation{Scenario: s, Passed: true, EvidenceDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
}

func templates() map[Edition]Template {
	return map[Edition]Template{Shared: {Profile: lifecycle.ProfileSharedTenant, Limits: resource.Limits{CPUQuotaMicros: 50000, CPUPeriodMicros: 100000, MemoryMaxBytes: 1 << 30, PidsMax: 64, FileDescriptorMax: 512, WallClockSeconds: 600}, Network: resource.NetworkPolicy{Mode: "denyAll"}, ExecutablePath: "/runtime/bin/shared-entry", Arguments: []string{"--serve"}}, Dedicated: {Profile: lifecycle.ProfileDedicatedAdministrator, Limits: resource.Limits{CPUQuotaMicros: 80000, CPUPeriodMicros: 100000, MemoryMaxBytes: 2 << 30, PidsMax: 128, FileDescriptorMax: 1024, WallClockSeconds: 1200}, Network: resource.NetworkPolicy{Mode: "denyAll"}, ExecutablePath: "/runtime/bin/dedicated-entry", Arguments: []string{"--serve"}}}
}
func compiler(t *testing.T) (*Compiler, *audit) {
	t.Helper()
	a := &audit{}
	c, err := NewCompiler(templates(), resourceVerifier{}, a)
	if err != nil {
		t.Fatal(err)
	}
	return c, a
}
func intent(e Edition) Intent {
	return Intent{Schema: Schema, Edition: e, CageID: "cage-edition-a", BaseRootDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", SeccompDigest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
}

func releaseBinding() ReleaseEvidenceBinding {
	return ReleaseEvidenceBinding{SchemaVersion: ReleaseEvidenceBindingSchema, CandidateReleaseID: "v1.0.0", CandidateCommitSHA: "0123456789abcdef0123456789abcdef01234567", ArtifactManifestDigest: fmt.Sprintf("%064x", 31), SBOMDigest: fmt.Sprintf("%064x", 32)}
}

func TestCompileSharedAndDedicatedRemainStrict(t *testing.T) {
	c, _ := compiler(t)
	for _, edition := range []Edition{Shared, Dedicated} {
		compiled, err := c.Compile(context.Background(), "spiffe://brick/test", intent(edition))
		if err != nil {
			t.Fatalf("Compile(%s): %v", edition, err)
		}
		if compiled.Profile != templates()[edition].Profile || compiled.IsolationRequest.Profile != compiled.Profile || compiled.NetworkTemplate.Mode != "denyAll" || compiled.IsolationRequest.CloseDescriptorsAt != 3 {
			t.Fatalf("unsafe compilation: %+v", compiled)
		}
	}
}
func TestCompileRejectsUnknownEditionAndAuditFailure(t *testing.T) {
	c, a := compiler(t)
	if _, err := c.Compile(context.Background(), "actor", intent("unknown")); !errors.Is(err, ErrDenied) {
		t.Fatalf("unknown edition: %v", err)
	}
	a.fail = true
	if _, err := c.Compile(context.Background(), "actor", intent(Shared)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("audit failure: %v", err)
	}
}
func TestBindingRejectsCrossTenantAndTampering(t *testing.T) {
	c, _ := compiler(t)
	compiled, err := c.Compile(context.Background(), "actor", intent(Shared))
	if err != nil {
		t.Fatal(err)
	}
	compiled.CageID = "cage-other-a"
	if _, err := c.BindResource(context.Background(), "actor", compiled, isolation.Plan{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("tampered compilation: %v", err)
	}
}
func TestStagingSignsCompleteDeterministicMatrix(t *testing.T) {
	c, _ := compiler(t)
	compiled, err := c.Compile(context.Background(), "actor", intent(Shared))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	r := &runner{}
	a := &audit{}
	stage, err := NewStagingAuthority(key, r, a, func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := stage.Run(context.Background(), "actor", "11111111-1111-4111-8111-111111111111", compiled, releaseBinding())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidence(evidence, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != len(requiredScenarios) {
		t.Fatalf("calls=%d", len(r.calls))
	}
	evidence.Observations[0].Passed = false
	if err := VerifyEvidence(evidence, key.Public().(ed25519.PublicKey)); !errors.Is(err, ErrDenied) {
		t.Fatalf("tampered evidence: %v", err)
	}
}
func TestStagingFailsClosedOnScenarioFailure(t *testing.T) {
	c, _ := compiler(t)
	compiled, err := c.Compile(context.Background(), "actor", intent(Dedicated))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	stage, err := NewStagingAuthority(key, &runner{fail: "socketExposure"}, &audit{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Run(context.Background(), "actor", "11111111-1111-4111-8111-111111111111", compiled, releaseBinding()); !errors.Is(err, ErrDenied) {
		t.Fatalf("scenario failure: %v", err)
	}
}

func TestPhase51StagingRejectsMissingBindingAndSignedBindingTampering(t *testing.T) {
	c, _ := compiler(t)
	compiled, err := c.Compile(context.Background(), "actor", intent(Shared))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
	stage, err := NewStagingAuthority(key, &runner{}, &audit{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Run(context.Background(), "actor", "11111111-1111-4111-8111-111111111111", compiled, ReleaseEvidenceBinding{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("missing binding: %v", err)
	}
	evidence, err := stage.Run(context.Background(), "actor", "11111111-1111-4111-8111-111111111111", compiled, releaseBinding())
	if err != nil {
		t.Fatal(err)
	}
	evidence.ReleaseBinding.SBOMDigest = fmt.Sprintf("%064x", 99)
	if err := VerifyEvidence(evidence, key.Public().(ed25519.PublicKey)); !errors.Is(err, ErrDenied) {
		t.Fatalf("tampered signed release binding: %v", err)
	}
}
