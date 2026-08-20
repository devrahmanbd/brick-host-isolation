package edition

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

// ReleaseEvidenceBindingSchema is duplicated intentionally rather than imported
// from Core. This private runtime repository must verify the public contract
// without turning Core into a runtime dependency.
const ReleaseEvidenceBindingSchema = "brick.release-evidence-binding.v1"

var (
	ErrInvalidReleaseEvidenceBinding = errors.New("invalid release evidence binding")
	releaseIDPattern                 = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	commitPattern                    = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
)

// ReleaseEvidenceBinding is embedded in Phase 8 Evidence and therefore covered
// by the staging signer. It is the sole allowed path for release identity and
// artifact/SBOM digest data; unsigned sidecars are never consulted.
type ReleaseEvidenceBinding struct {
	SchemaVersion          string `json:"schemaVersion"`
	CandidateReleaseID     string `json:"candidateReleaseId"`
	CandidateCommitSHA     string `json:"candidateCommitSha"`
	ArtifactManifestDigest string `json:"artifactManifestDigest"`
	SBOMDigest             string `json:"sbomDigest"`
}

func ValidateReleaseEvidenceBinding(binding ReleaseEvidenceBinding) error {
	if binding.SchemaVersion != ReleaseEvidenceBindingSchema ||
		!releaseIDPattern.MatchString(binding.CandidateReleaseID) ||
		!commitPattern.MatchString(binding.CandidateCommitSHA) ||
		!digestPattern.MatchString(binding.ArtifactManifestDigest) ||
		!digestPattern.MatchString(binding.SBOMDigest) {
		return ErrInvalidReleaseEvidenceBinding
	}
	return nil
}

// CanonicalReleaseEvidenceBinding supplies a deterministic digest and a fixture
// compatibility point. The surrounding Evidence uses its own canonical payload
// and signature, which includes this complete binding as a nested struct.
func CanonicalReleaseEvidenceBinding(binding ReleaseEvidenceBinding) ([]byte, error) {
	if err := ValidateReleaseEvidenceBinding(binding); err != nil {
		return nil, err
	}
	return json.Marshal(binding)
}

func ReleaseEvidenceBindingDigest(binding ReleaseEvidenceBinding) (string, error) {
	payload, err := CanonicalReleaseEvidenceBinding(binding)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func LoadReleaseEvidenceBinding(raw []byte) (ReleaseEvidenceBinding, error) {
	if len(raw) == 0 || len(raw) > 16*1024 {
		return ReleaseEvidenceBinding{}, ErrInvalidReleaseEvidenceBinding
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var binding ReleaseEvidenceBinding
	if err := decoder.Decode(&binding); err != nil {
		return ReleaseEvidenceBinding{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ReleaseEvidenceBinding{}, ErrInvalidReleaseEvidenceBinding
	}
	if err := ValidateReleaseEvidenceBinding(binding); err != nil {
		return ReleaseEvidenceBinding{}, err
	}
	return binding, nil
}
