package certification

import (
	"context"
	"testing"

	"github.com/brick/host-isolation/edition"
)

func TestPhase51CertifyRejectsStagingBindingMismatches(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*edition.ReleaseEvidenceBinding)
	}{
		{"wrong-release", func(binding *edition.ReleaseEvidenceBinding) { binding.CandidateReleaseID = "v1.0.1" }},
		{"wrong-commit", func(binding *edition.ReleaseEvidenceBinding) {
			binding.CandidateCommitSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}},
		{"wrong-manifest", func(binding *edition.ReleaseEvidenceBinding) {
			binding.ArtifactManifestDigest = digest("wrong-manifest")
		}},
		{"wrong-sbom", func(binding *edition.ReleaseEvidenceBinding) { binding.SBOMDigest = digest("wrong-sbom") }},
		{"missing-sbom", func(binding *edition.ReleaseEvidenceBinding) { binding.SBOMDigest = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newFixture(t)
			evidence := fixture.request.StagingEvidence[edition.Shared]
			tc.mutate(&evidence.ReleaseBinding)
			if err := edition.SignEvidence(&evidence, fixture.stagingPrivate); err != nil {
				t.Fatal(err)
			}
			fixture.request.StagingEvidence[edition.Shared] = evidence
			_, err := fixture.authority.Certify(context.Background(), testActor, testCertificateID, fixture.request)
			assertDenied(t, err)
		})
	}
}

func TestPhase51CertifyRejectsCrossEditionEvidenceReuse(t *testing.T) {
	fixture := newFixture(t)
	fixture.request.StagingEvidence[edition.Dedicated] = fixture.request.StagingEvidence[edition.Shared]
	_, err := fixture.authority.Certify(context.Background(), testActor, testCertificateID, fixture.request)
	assertDenied(t, err)
}
