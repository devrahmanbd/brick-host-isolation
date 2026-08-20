package certification

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/brick/host-isolation/edition"
	"github.com/brick/host-isolation/lifecycle"
)

const (
	testActor         = "spiffe://brick.example/release/certifier"
	testRelease       = "v1.0.0"
	testCommit        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testCertificateID = "123e4567-e89b-42d3-a456-426614174000"
)

type memoryAudit struct {
	events []string
	err    error
}

func (m *memoryAudit) RecordEvent(actor, action, outcome, resource string, metadata map[string]any) error {
	m.events = append(m.events, action+":"+outcome+":"+resource)
	return m.err
}

type allowLimiter struct {
	err   error
	calls int
}

func (l *allowLimiter) Allow(context.Context, string) error { l.calls++; return l.err }

func TestCertifyAuthorizesOnlyCompleteBoundEvidence(t *testing.T) {
	fixture := newFixture(t)
	certificate, err := fixture.authority.Certify(context.Background(), testActor, testCertificateID, fixture.request)
	if err != nil {
		t.Fatalf("certify: %v", err)
	}
	if err := VerifyCertificate(certificate, fixture.certificatePublic, fixture.now); err != nil {
		t.Fatalf("verify certificate: %v", err)
	}
	if fixture.audit.events[len(fixture.audit.events)-1] != "certifyGuardedRelease:authorized:"+testRelease {
		t.Fatalf("missing authorized audit outcome: %#v", fixture.audit.events)
	}
}

func TestCertifyRejectsTamperedStagingEvidence(t *testing.T) {
	fixture := newFixture(t)
	evidence := fixture.request.StagingEvidence[edition.Shared]
	evidence.BindingDigest = digest("tampered")
	fixture.request.StagingEvidence[edition.Shared] = evidence
	_, err := fixture.authority.Certify(context.Background(), testActor, testCertificateID, fixture.request)
	assertDenied(t, err)
}

func TestCertifyRejectsMissingCoreGAGate(t *testing.T) {
	fixture := newFixture(t)
	fixture.request.CoreGates = fixture.request.CoreGates[:5]
	_, err := fixture.authority.Certify(context.Background(), testActor, testCertificateID, fixture.request)
	assertDenied(t, err)
}

func TestCertifyRejectsExpiredSecurityReview(t *testing.T) {
	fixture := newFixture(t)
	fixture.request.SecurityReview.ExpiresAt = fixture.now.Add(-time.Minute)
	if err := SignSecurityReview(&fixture.request.SecurityReview, fixture.reviewPrivate); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.authority.Certify(context.Background(), testActor, testCertificateID, fixture.request)
	assertDenied(t, err)
}

func TestCertifyRejectsUnorderedArtifactManifest(t *testing.T) {
	fixture := newFixture(t)
	fixture.request.ArtifactManifest.Artifacts[0], fixture.request.ArtifactManifest.Artifacts[1] = fixture.request.ArtifactManifest.Artifacts[1], fixture.request.ArtifactManifest.Artifacts[0]
	if err := SignArtifactManifest(&fixture.request.ArtifactManifest, fixture.manifestPrivate); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.authority.Certify(context.Background(), testActor, testCertificateID, fixture.request)
	assertDenied(t, err)
}

func TestCertifyRateLimitsAndAudits(t *testing.T) {
	fixture := newFixture(t)
	fixture.limiter.err = errors.New("quota exhausted")
	_, err := fixture.authority.Certify(context.Background(), testActor, testCertificateID, fixture.request)
	assertDenied(t, err)
	if got := fixture.audit.events[len(fixture.audit.events)-1]; !strings.Contains(got, "denied") {
		t.Fatalf("expected denial audit, got %s", got)
	}
}

func TestCertifyCancellationAuditsAndFailsClosed(t *testing.T) {
	fixture := newFixture(t)
	context, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fixture.authority.Certify(context, testActor, testCertificateID, fixture.request)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable cancellation, got %v", err)
	}
	if fixture.limiter.calls != 0 {
		t.Fatalf("limiter called after cancellation")
	}
}

func TestCertificateTamperingIsRejected(t *testing.T) {
	fixture := newFixture(t)
	certificate, err := fixture.authority.Certify(context.Background(), testActor, testCertificateID, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	certificate.ReleaseID = "v9.9.9"
	if err := VerifyCertificate(certificate, fixture.certificatePublic, fixture.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("expected tamper denial, got %v", err)
	}
}

func TestAuditFailureMasksAllCertificationOutcomes(t *testing.T) {
	fixture := newFixture(t)
	fixture.audit.err = errors.New("protected sink offline")
	_, err := fixture.authority.Certify(context.Background(), testActor, testCertificateID, fixture.request)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}
}

func BenchmarkCertifyCompleteEvidence(b *testing.B) {
	fixture := newFixture(&testing.T{})
	for index := 0; index < b.N; index++ {
		_, err := fixture.authority.Certify(context.Background(), testActor, testCertificateID, fixture.request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

type fixture struct {
	authority         *Authority
	request           Request
	now               time.Time
	audit             *memoryAudit
	limiter           *allowLimiter
	manifestPrivate   ed25519.PrivateKey
	reviewPrivate     ed25519.PrivateKey
	certificatePublic ed25519.PublicKey
}

func newFixture(t testing.TB) fixture {
	t.Helper()
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	manifestPublic, manifestPrivate := keyPair(t)
	benchmarkPublic, benchmarkPrivate := keyPair(t)
	reviewPublic, reviewPrivate := keyPair(t)
	stagingPublic, stagingPrivate := keyPair(t)
	corePublic, corePrivate := keyPair(t)
	certificatePublic, certificatePrivate := keyPair(t)
	sharedEvidence := stagingEvidence(t, stagingPrivate, edition.Shared, now, "123e4567-e89b-42d3-a456-426614174001")
	dedicatedEvidence := stagingEvidence(t, stagingPrivate, edition.Dedicated, now, "123e4567-e89b-42d3-a456-426614174002")
	manifest := ArtifactManifest{Schema: ManifestSchema, ReleaseID: testRelease, SourceCommit: testCommit, CreatedAt: now.Add(-time.Minute), SBOMDigest: digest("sbom"), Artifacts: []Artifact{{Path: "bin/brick-host-isolation", Digest: digest("binary"), SizeBytes: 4096}, {Path: "docs/release.md", Digest: digest("docs"), SizeBytes: 512}}}
	if err := SignArtifactManifest(&manifest, manifestPrivate); err != nil {
		t.Fatal(err)
	}
	benchmark := BenchmarkEvidence{Schema: BenchmarkSchema, ReleaseID: testRelease, SourceCommit: testCommit, MeasuredAt: now.Add(-time.Minute), EnvironmentDigest: digest("benchmark-environment"), Results: []BenchmarkResult{{Name: "BenchmarkCertify", Iterations: 1000, NanosecondsPerOp: 20000, AllocationsPerOp: 10, BytesPerOp: 4096}}}
	if err := SignBenchmarkEvidence(&benchmark, benchmarkPrivate); err != nil {
		t.Fatal(err)
	}
	review := SecurityReview{Schema: ReviewSchema, ReleaseID: testRelease, SourceCommit: testCommit, ReviewID: "123e4567-e89b-42d3-a456-426614174003", ReviewerID: "spiffe://brick.example/security/reviewer", ReviewedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Outcome: "approved", FindingsDigest: digest("review"), Scope: []string{"artifact-manifest", "engine", "staging-evidence"}}
	if err := SignSecurityReview(&review, reviewPrivate); err != nil {
		t.Fatal(err)
	}
	gates := make([]CoreGateEvidence, 0, 6)
	for _, currentEdition := range []edition.Edition{edition.Shared, edition.Dedicated} {
		for _, gate := range requiredGates {
			evidence := CoreGateEvidence{Schema: CoreGateSchema, Edition: currentEdition, Gate: gate, ReleaseID: testRelease, SourceCommit: testCommit, PolicyDigest: digest(string(currentEdition) + string(gate)), IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Outcome: "approved"}
			if err := SignCoreGateEvidence(&evidence, corePrivate); err != nil {
				t.Fatal(err)
			}
			gates = append(gates, evidence)
		}
	}
	audit, limiter := &memoryAudit{}, &allowLimiter{}
	authority, err := NewAuthority(TrustBundle{ManifestKey: manifestPublic, BenchmarkKey: benchmarkPublic, SecurityReviewKey: reviewPublic, StagingKey: stagingPublic, CoreGateKey: corePublic, CertificateKey: certificatePrivate, CertificateTTL: time.Hour, MaxEvidenceAge: 24 * time.Hour}, audit, limiter, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return fixture{authority: authority, request: Request{Schema: Schema, ReleaseID: testRelease, SourceCommit: testCommit, ArtifactManifest: manifest, BenchmarkEvidence: benchmark, SecurityReview: review, StagingEvidence: map[edition.Edition]edition.Evidence{edition.Shared: sharedEvidence, edition.Dedicated: dedicatedEvidence}, CoreGates: gates}, now: now, audit: audit, limiter: limiter, manifestPrivate: manifestPrivate, reviewPrivate: reviewPrivate, certificatePublic: certificatePublic}
}

func stagingEvidence(t testing.TB, key ed25519.PrivateKey, current edition.Edition, now time.Time, evidenceID string) edition.Evidence {
	t.Helper()
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
	if err := edition.SignEvidence(&evidence, key); err != nil {
		t.Fatal(err)
	}
	return evidence
}
func keyPair(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}
func digest(value string) string { sum := sha256sum(value); return sum }
func sha256sum(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func assertDenied(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("expected denied, got %v", err)
	}
}
