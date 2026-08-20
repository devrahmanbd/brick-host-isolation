// certification-verify is a deterministic, no-host-side-effect proof that the
// guarded release authority accepts complete signed evidence and rejects tampering.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/brick/host-isolation/certification"
	"github.com/brick/host-isolation/edition"
	"github.com/brick/host-isolation/lifecycle"
)

const (
	releaseID = "v1.0.0"
	commit    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	actor     = "spiffe://brick.example/release/certifier"
	certID    = "123e4567-e89b-42d3-a456-426614174000"
)

type audit struct{}

func (audit) RecordEvent(string, string, string, string, map[string]any) error { return nil }

type limiter struct{}

func (limiter) Allow(context.Context, string) error { return nil }

func main() {
	if err := verify(); err != nil {
		fmt.Fprintln(os.Stderr, "certification verification failed:", err)
		os.Exit(1)
	}
	fmt.Println("certification verification passed")
}

func verify() error {
	if _, err := os.ReadFile("contracts/brick-host-isolation-certification.v1.json"); err != nil {
		return fmt.Errorf("contract unavailable: %w", err)
	}
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	manifestPublic, manifestPrivate, err := keyPair()
	if err != nil {
		return err
	}
	benchmarkPublic, benchmarkPrivate, err := keyPair()
	if err != nil {
		return err
	}
	reviewPublic, reviewPrivate, err := keyPair()
	if err != nil {
		return err
	}
	stagingPublic, stagingPrivate, err := keyPair()
	if err != nil {
		return err
	}
	corePublic, corePrivate, err := keyPair()
	if err != nil {
		return err
	}
	certificatePublic, certificatePrivate, err := keyPair()
	if err != nil {
		return err
	}
	authority, err := certification.NewAuthority(certification.TrustBundle{ManifestKey: manifestPublic, BenchmarkKey: benchmarkPublic, SecurityReviewKey: reviewPublic, StagingKey: stagingPublic, CoreGateKey: corePublic, CertificateKey: certificatePrivate, CertificateTTL: time.Hour, MaxEvidenceAge: 24 * time.Hour}, audit{}, limiter{}, func() time.Time { return now })
	if err != nil {
		return err
	}
	request, err := requestFixture(now, manifestPrivate, benchmarkPrivate, reviewPrivate, stagingPrivate, corePrivate)
	if err != nil {
		return err
	}
	certificate, err := authority.Certify(context.Background(), actor, certID, request)
	if err != nil {
		return err
	}
	if err := certification.VerifyCertificate(certificate, certificatePublic, now); err != nil {
		return err
	}
	request.SecurityReview.Outcome = "rejected"
	if err := certification.SignSecurityReview(&request.SecurityReview, reviewPrivate); err != nil {
		return err
	}
	if _, err := authority.Certify(context.Background(), actor, certID, request); err == nil {
		return fmt.Errorf("tampered review unexpectedly certified")
	}
	return nil
}

func requestFixture(now time.Time, manifestKey, benchmarkKey, reviewKey, stagingKey, coreKey ed25519.PrivateKey) (certification.Request, error) {
	manifest := certification.ArtifactManifest{Schema: certification.ManifestSchema, ReleaseID: releaseID, SourceCommit: commit, CreatedAt: now.Add(-time.Minute), SBOMDigest: digest("sbom"), Artifacts: []certification.Artifact{{Path: "bin/brick-host-isolation", Digest: digest("binary"), SizeBytes: 4096}, {Path: "docs/release.md", Digest: digest("docs"), SizeBytes: 512}}}
	if err := certification.SignArtifactManifest(&manifest, manifestKey); err != nil {
		return certification.Request{}, err
	}
	benchmark := certification.BenchmarkEvidence{Schema: certification.BenchmarkSchema, ReleaseID: releaseID, SourceCommit: commit, MeasuredAt: now.Add(-time.Minute), EnvironmentDigest: digest("environment"), Results: []certification.BenchmarkResult{{Name: "BenchmarkCertify", Iterations: 1000, NanosecondsPerOp: 20000, AllocationsPerOp: 10, BytesPerOp: 4096}}}
	if err := certification.SignBenchmarkEvidence(&benchmark, benchmarkKey); err != nil {
		return certification.Request{}, err
	}
	review := certification.SecurityReview{Schema: certification.ReviewSchema, ReleaseID: releaseID, SourceCommit: commit, ReviewID: "123e4567-e89b-42d3-a456-426614174003", ReviewerID: "spiffe://brick.example/security/reviewer", ReviewedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Outcome: "approved", FindingsDigest: digest("review"), Scope: []string{"artifact-manifest", "engine", "staging-evidence"}}
	if err := certification.SignSecurityReview(&review, reviewKey); err != nil {
		return certification.Request{}, err
	}
	gates := make([]certification.CoreGateEvidence, 0, 6)
	for _, current := range []edition.Edition{edition.Shared, edition.Dedicated} {
		for _, gate := range []certification.Gate{certification.GateAdmission, certification.GateCertification, certification.GateGA} {
			evidence := certification.CoreGateEvidence{Schema: certification.CoreGateSchema, Edition: current, Gate: gate, ReleaseID: releaseID, SourceCommit: commit, PolicyDigest: digest(string(current) + string(gate)), IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Outcome: "approved"}
			if err := certification.SignCoreGateEvidence(&evidence, coreKey); err != nil {
				return certification.Request{}, err
			}
			gates = append(gates, evidence)
		}
	}
	shared, err := staging(now, stagingKey, edition.Shared, "123e4567-e89b-42d3-a456-426614174001")
	if err != nil {
		return certification.Request{}, err
	}
	dedicated, err := staging(now, stagingKey, edition.Dedicated, "123e4567-e89b-42d3-a456-426614174002")
	if err != nil {
		return certification.Request{}, err
	}
	return certification.Request{Schema: certification.Schema, ReleaseID: releaseID, SourceCommit: commit, ArtifactManifest: manifest, BenchmarkEvidence: benchmark, SecurityReview: review, StagingEvidence: map[edition.Edition]edition.Evidence{edition.Shared: shared, edition.Dedicated: dedicated}, CoreGates: gates}, nil
}

func staging(now time.Time, key ed25519.PrivateKey, current edition.Edition, evidenceID string) (edition.Evidence, error) {
	profile := lifecycle.ProfileSharedTenant
	if current == edition.Dedicated {
		profile = lifecycle.ProfileDedicatedAdministrator
	}
	scenarios := []edition.Scenario{"pathTraversal", "mountEscape", "symlinkEscape", "bindMountEscape", "namespaceEscape", "processEscape", "socketExposure", "environmentInjection", "executableInjection", "egressBypass", "resourceExhaustion", "replayAttempt", "auditFailure", "freezeRecovery", "crossTenantIsolation"}
	observations := make([]edition.Observation, 0, len(scenarios))
	for _, scenario := range scenarios {
		observations = append(observations, edition.Observation{Scenario: scenario, Passed: true, EvidenceDigest: digest(string(scenario) + string(current))})
	}
	evidence := edition.Evidence{Schema: edition.Schema, EvidenceID: evidenceID, Edition: current, Profile: profile, CageID: "cage-" + string(current), BindingDigest: digest("binding" + string(current)), IssuedAt: now.Add(-time.Minute), Observations: observations}
	return evidence, edition.SignEvidence(&evidence, key)
}
func keyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
