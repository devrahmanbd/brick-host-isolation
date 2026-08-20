// Package certification guards immutable Host Isolation releases. It consumes
// already-signed staging, Core-policy, benchmark, review, and artifact evidence;
// it neither executes host operations nor bypasses any lower-phase authority.
package certification

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/brick/host-isolation/edition"
)

const (
	Schema             = "brick.host-isolation.certification.v1"
	ManifestSchema     = "brick.host-isolation.artifact-manifest.v1"
	BenchmarkSchema    = "brick.host-isolation.benchmark-evidence.v1"
	ReviewSchema       = "brick.host-isolation.security-review.v1"
	CoreGateSchema     = "brick.core.host-isolation-admission.v1"
	SignatureAlgorithm = "ed25519"
)

var (
	ErrDenied      = errors.New("release certification denied")
	ErrUnavailable = errors.New("release certification authority unavailable")
	digestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	commitPattern  = regexp.MustCompile(`^[a-f0-9]{40,64}$`)
	releasePattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	actorPattern   = regexp.MustCompile(`^spiffe://[a-z0-9][a-z0-9._/-]{2,255}$`)
)

type Gate string

const (
	GateAdmission     Gate = "admission"
	GateCertification Gate = "certification"
	GateGA            Gate = "ga"
)

var requiredGates = []Gate{GateAdmission, GateCertification, GateGA}

type Artifact struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	SizeBytes int64  `json:"sizeBytes"`
}

type ArtifactManifest struct {
	Schema             string     `json:"schema"`
	ReleaseID          string     `json:"releaseId"`
	SourceCommit       string     `json:"sourceCommit"`
	CreatedAt          time.Time  `json:"createdAt"`
	SBOMDigest         string     `json:"sbomDigest"`
	Artifacts          []Artifact `json:"artifacts"`
	SignatureAlgorithm string     `json:"signatureAlgorithm"`
	Signature          string     `json:"signature"`
}

type BenchmarkResult struct {
	Name             string `json:"name"`
	Iterations       int64  `json:"iterations"`
	NanosecondsPerOp int64  `json:"nanosecondsPerOp"`
	AllocationsPerOp int64  `json:"allocationsPerOp"`
	BytesPerOp       int64  `json:"bytesPerOp"`
}

type BenchmarkEvidence struct {
	Schema             string            `json:"schema"`
	ReleaseID          string            `json:"releaseId"`
	SourceCommit       string            `json:"sourceCommit"`
	MeasuredAt         time.Time         `json:"measuredAt"`
	EnvironmentDigest  string            `json:"environmentDigest"`
	Results            []BenchmarkResult `json:"results"`
	SignatureAlgorithm string            `json:"signatureAlgorithm"`
	Signature          string            `json:"signature"`
}

type SecurityReview struct {
	Schema             string    `json:"schema"`
	ReleaseID          string    `json:"releaseId"`
	SourceCommit       string    `json:"sourceCommit"`
	ReviewID           string    `json:"reviewId"`
	ReviewerID         string    `json:"reviewerId"`
	ReviewedAt         time.Time `json:"reviewedAt"`
	ExpiresAt          time.Time `json:"expiresAt"`
	Outcome            string    `json:"outcome"`
	FindingsDigest     string    `json:"findingsDigest"`
	Scope              []string  `json:"scope"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	Signature          string    `json:"signature"`
}

type CoreGateEvidence struct {
	Schema             string          `json:"schema"`
	Edition            edition.Edition `json:"edition"`
	Gate               Gate            `json:"gate"`
	ReleaseID          string          `json:"releaseId"`
	SourceCommit       string          `json:"sourceCommit"`
	PolicyDigest       string          `json:"policyDigest"`
	IssuedAt           time.Time       `json:"issuedAt"`
	ExpiresAt          time.Time       `json:"expiresAt"`
	Outcome            string          `json:"outcome"`
	SignatureAlgorithm string          `json:"signatureAlgorithm"`
	Signature          string          `json:"signature"`
}

// Request contains all signed evidence required for a guarded release. The
// authority does not trust the caller to summarize any evidence by digest alone.
type Request struct {
	Schema            string                               `json:"schema"`
	ReleaseID         string                               `json:"releaseId"`
	SourceCommit      string                               `json:"sourceCommit"`
	ArtifactManifest  ArtifactManifest                     `json:"artifactManifest"`
	BenchmarkEvidence BenchmarkEvidence                    `json:"benchmarkEvidence"`
	SecurityReview    SecurityReview                       `json:"securityReview"`
	StagingEvidence   map[edition.Edition]edition.Evidence `json:"stagingEvidence"`
	CoreGates         []CoreGateEvidence                   `json:"coreGates"`
}

type Certificate struct {
	Schema                 string            `json:"schema"`
	CertificateID          string            `json:"certificateId"`
	ReleaseID              string            `json:"releaseId"`
	SourceCommit           string            `json:"sourceCommit"`
	ArtifactManifestDigest string            `json:"artifactManifestDigest"`
	SBOMDigest             string            `json:"sbomDigest"`
	BenchmarkDigest        string            `json:"benchmarkDigest"`
	SecurityReviewDigest   string            `json:"securityReviewDigest"`
	StagingEvidenceDigests map[string]string `json:"stagingEvidenceDigests"`
	CoreGateDigests        map[string]string `json:"coreGateDigests"`
	IssuedAt               time.Time         `json:"issuedAt"`
	ExpiresAt              time.Time         `json:"expiresAt"`
	SignatureAlgorithm     string            `json:"signatureAlgorithm"`
	Signature              string            `json:"signature"`
}

type AuditSink interface {
	RecordEvent(actor, action, outcome, resource string, metadata map[string]any) error
}

type RateLimiter interface {
	Allow(context.Context, string) error
}

type TrustBundle struct {
	ManifestKey       ed25519.PublicKey
	BenchmarkKey      ed25519.PublicKey
	SecurityReviewKey ed25519.PublicKey
	StagingKey        ed25519.PublicKey
	CoreGateKey       ed25519.PublicKey
	CertificateKey    ed25519.PrivateKey
	CertificateTTL    time.Duration
	MaxEvidenceAge    time.Duration
}

type Authority struct {
	trust TrustBundle
	audit AuditSink
	limit RateLimiter
	now   func() time.Time
}

func NewAuthority(trust TrustBundle, audit AuditSink, limit RateLimiter, now func() time.Time) (*Authority, error) {
	if audit == nil || limit == nil || now == nil || trust.CertificateTTL <= 0 || trust.CertificateTTL > 24*time.Hour || trust.MaxEvidenceAge <= 0 || trust.MaxEvidenceAge > 30*24*time.Hour || !validPublicKey(trust.ManifestKey) || !validPublicKey(trust.BenchmarkKey) || !validPublicKey(trust.SecurityReviewKey) || !validPublicKey(trust.StagingKey) || !validPublicKey(trust.CoreGateKey) || len(trust.CertificateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: invalid dependency or trust configuration", ErrUnavailable)
	}
	trust.ManifestKey = append(ed25519.PublicKey(nil), trust.ManifestKey...)
	trust.BenchmarkKey = append(ed25519.PublicKey(nil), trust.BenchmarkKey...)
	trust.SecurityReviewKey = append(ed25519.PublicKey(nil), trust.SecurityReviewKey...)
	trust.StagingKey = append(ed25519.PublicKey(nil), trust.StagingKey...)
	trust.CoreGateKey = append(ed25519.PublicKey(nil), trust.CoreGateKey...)
	trust.CertificateKey = append(ed25519.PrivateKey(nil), trust.CertificateKey...)
	return &Authority{trust: trust, audit: audit, limit: limit, now: now}, nil
}

func (a *Authority) Certify(ctx context.Context, actor, certificateID string, request Request) (Certificate, error) {
	if a == nil || a.audit == nil || a.limit == nil || a.now == nil {
		return Certificate{}, fmt.Errorf("%w: authority dependency unavailable", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return a.deny(actor, request.ReleaseID, "request_cancelled", ErrUnavailable)
	}
	if !actorPattern.MatchString(actor) || !uuidPattern.MatchString(certificateID) {
		return a.deny(actor, request.ReleaseID, "invalid_caller_or_certificate_id", ErrDenied)
	}
	if err := a.limit.Allow(ctx, actor); err != nil {
		return a.deny(actor, request.ReleaseID, "rate_limited", ErrDenied)
	}
	if err := a.verifyRequest(request, a.now().UTC()); err != nil {
		return a.deny(actor, request.ReleaseID, "mandatory_evidence_rejected", ErrDenied)
	}
	certificate, err := a.makeCertificate(certificateID, request, a.now().UTC())
	if err != nil {
		return Certificate{}, fmt.Errorf("%w: certificate construction failed", ErrUnavailable)
	}
	if err := SignCertificate(&certificate, a.trust.CertificateKey); err != nil {
		return Certificate{}, fmt.Errorf("%w: certificate signing failed", ErrUnavailable)
	}
	metadata := map[string]any{"certificateId": certificate.CertificateID, "sourceCommit": certificate.SourceCommit, "artifactManifestDigest": certificate.ArtifactManifestDigest, "sharedEvidenceDigest": certificate.StagingEvidenceDigests[string(edition.Shared)], "dedicatedEvidenceDigest": certificate.StagingEvidenceDigests[string(edition.Dedicated)]}
	if err := a.audit.RecordEvent(actor, "certifyGuardedRelease", "authorized", request.ReleaseID, metadata); err != nil {
		return Certificate{}, fmt.Errorf("%w: audit sink rejected authorization", ErrUnavailable)
	}
	return certificate, nil
}

func (a *Authority) deny(actor, releaseID, reason string, result error) (Certificate, error) {
	if err := a.audit.RecordEvent(fallback(actor), "certifyGuardedRelease", "denied", fallback(releaseID), map[string]any{"reasonCode": reason}); err != nil {
		return Certificate{}, fmt.Errorf("%w: audit sink rejected denial", ErrUnavailable)
	}
	return Certificate{}, fmt.Errorf("%w: %s", result, reason)
}

func (a *Authority) verifyRequest(request Request, now time.Time) error {
	if request.Schema != Schema || !releasePattern.MatchString(request.ReleaseID) || !commitPattern.MatchString(request.SourceCommit) {
		return ErrDenied
	}
	if err := VerifyArtifactManifest(request.ArtifactManifest, a.trust.ManifestKey, now, a.trust.MaxEvidenceAge); err != nil || request.ArtifactManifest.ReleaseID != request.ReleaseID || request.ArtifactManifest.SourceCommit != request.SourceCommit {
		return ErrDenied
	}
	if err := VerifyBenchmarkEvidence(request.BenchmarkEvidence, a.trust.BenchmarkKey, now, a.trust.MaxEvidenceAge); err != nil || request.BenchmarkEvidence.ReleaseID != request.ReleaseID || request.BenchmarkEvidence.SourceCommit != request.SourceCommit {
		return ErrDenied
	}
	if err := VerifySecurityReview(request.SecurityReview, a.trust.SecurityReviewKey, now); err != nil || request.SecurityReview.ReleaseID != request.ReleaseID || request.SecurityReview.SourceCommit != request.SourceCommit {
		return ErrDenied
	}
	if err := verifyStagingEvidence(request.StagingEvidence, a.trust.StagingKey, now, a.trust.MaxEvidenceAge); err != nil {
		return ErrDenied
	}
	return verifyCoreGates(request.CoreGates, a.trust.CoreGateKey, request.ReleaseID, request.SourceCommit, now)
}

func (a *Authority) makeCertificate(certificateID string, request Request, now time.Time) (Certificate, error) {
	manifestDigest, err := digestValue(request.ArtifactManifest)
	if err != nil {
		return Certificate{}, err
	}
	benchmarkDigest, err := digestValue(request.BenchmarkEvidence)
	if err != nil {
		return Certificate{}, err
	}
	reviewDigest, err := digestValue(request.SecurityReview)
	if err != nil {
		return Certificate{}, err
	}
	staging := make(map[string]string, 2)
	for _, currentEdition := range []edition.Edition{edition.Shared, edition.Dedicated} {
		digest, err := digestValue(request.StagingEvidence[currentEdition])
		if err != nil {
			return Certificate{}, err
		}
		staging[string(currentEdition)] = digest
	}
	coreGates := make(map[string]string, len(request.CoreGates))
	for _, gate := range request.CoreGates {
		digest, err := digestValue(gate)
		if err != nil {
			return Certificate{}, err
		}
		coreGates[string(gate.Edition)+":"+string(gate.Gate)] = digest
	}
	return Certificate{Schema: Schema, CertificateID: certificateID, ReleaseID: request.ReleaseID, SourceCommit: request.SourceCommit, ArtifactManifestDigest: manifestDigest, SBOMDigest: request.ArtifactManifest.SBOMDigest, BenchmarkDigest: benchmarkDigest, SecurityReviewDigest: reviewDigest, StagingEvidenceDigests: staging, CoreGateDigests: coreGates, IssuedAt: now, ExpiresAt: now.Add(a.trust.CertificateTTL), SignatureAlgorithm: SignatureAlgorithm}, nil
}

func VerifyArtifactManifest(manifest ArtifactManifest, key ed25519.PublicKey, now time.Time, maxAge time.Duration) error {
	if !validPublicKey(key) || manifest.Schema != ManifestSchema || !releasePattern.MatchString(manifest.ReleaseID) || !commitPattern.MatchString(manifest.SourceCommit) || !digestPattern.MatchString(manifest.SBOMDigest) || !fresh(manifest.CreatedAt, now, maxAge) || !validArtifacts(manifest.Artifacts) || !verifySignature(manifest, key, manifest.SignatureAlgorithm, manifest.Signature) {
		return ErrDenied
	}
	return nil
}

func VerifyBenchmarkEvidence(evidence BenchmarkEvidence, key ed25519.PublicKey, now time.Time, maxAge time.Duration) error {
	if !validPublicKey(key) || evidence.Schema != BenchmarkSchema || !releasePattern.MatchString(evidence.ReleaseID) || !commitPattern.MatchString(evidence.SourceCommit) || !digestPattern.MatchString(evidence.EnvironmentDigest) || !fresh(evidence.MeasuredAt, now, maxAge) || !validBenchmarkResults(evidence.Results) || !verifySignature(evidence, key, evidence.SignatureAlgorithm, evidence.Signature) {
		return ErrDenied
	}
	return nil
}

func VerifySecurityReview(review SecurityReview, key ed25519.PublicKey, now time.Time) error {
	if !validPublicKey(key) || review.Schema != ReviewSchema || !releasePattern.MatchString(review.ReleaseID) || !commitPattern.MatchString(review.SourceCommit) || !uuidPattern.MatchString(review.ReviewID) || !actorPattern.MatchString(review.ReviewerID) || review.Outcome != "approved" || !digestPattern.MatchString(review.FindingsDigest) || !validReviewScope(review.Scope) || review.ReviewedAt.After(now) || !review.ExpiresAt.After(now) || !review.ExpiresAt.After(review.ReviewedAt) || !verifySignature(review, key, review.SignatureAlgorithm, review.Signature) {
		return ErrDenied
	}
	return nil
}

func VerifyCertificate(certificate Certificate, key ed25519.PublicKey, now time.Time) error {
	if !validPublicKey(key) || certificate.Schema != Schema || !uuidPattern.MatchString(certificate.CertificateID) || !releasePattern.MatchString(certificate.ReleaseID) || !commitPattern.MatchString(certificate.SourceCommit) || !digestPattern.MatchString(certificate.ArtifactManifestDigest) || !digestPattern.MatchString(certificate.SBOMDigest) || !digestPattern.MatchString(certificate.BenchmarkDigest) || !digestPattern.MatchString(certificate.SecurityReviewDigest) || !validCertificateDigests(certificate.StagingEvidenceDigests, certificate.CoreGateDigests) || certificate.IssuedAt.After(now) || !certificate.ExpiresAt.After(now) || !certificate.ExpiresAt.After(certificate.IssuedAt) || !verifySignature(certificate, key, certificate.SignatureAlgorithm, certificate.Signature) {
		return ErrDenied
	}
	return nil
}

func SignArtifactManifest(manifest *ArtifactManifest, key ed25519.PrivateKey) error {
	return signRecord(manifest, key)
}
func SignBenchmarkEvidence(evidence *BenchmarkEvidence, key ed25519.PrivateKey) error {
	return signRecord(evidence, key)
}
func SignSecurityReview(review *SecurityReview, key ed25519.PrivateKey) error {
	return signRecord(review, key)
}
func SignCoreGateEvidence(evidence *CoreGateEvidence, key ed25519.PrivateKey) error {
	return signRecord(evidence, key)
}
func SignCertificate(certificate *Certificate, key ed25519.PrivateKey) error {
	return signRecord(certificate, key)
}

func signRecord(record any, key ed25519.PrivateKey) error {
	if record == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid signing input")
	}
	switch typed := record.(type) {
	case *ArtifactManifest:
		typed.SignatureAlgorithm, typed.Signature = SignatureAlgorithm, ""
	case *BenchmarkEvidence:
		typed.SignatureAlgorithm, typed.Signature = SignatureAlgorithm, ""
	case *SecurityReview:
		typed.SignatureAlgorithm, typed.Signature = SignatureAlgorithm, ""
	case *CoreGateEvidence:
		typed.SignatureAlgorithm, typed.Signature = SignatureAlgorithm, ""
	case *Certificate:
		typed.SignatureAlgorithm, typed.Signature = SignatureAlgorithm, ""
	default:
		return errors.New("unsupported signing record")
	}
	payload, err := canonical(record)
	if err != nil {
		return err
	}
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
	switch typed := record.(type) {
	case *ArtifactManifest:
		typed.Signature = signature
	case *BenchmarkEvidence:
		typed.Signature = signature
	case *SecurityReview:
		typed.Signature = signature
	case *CoreGateEvidence:
		typed.Signature = signature
	case *Certificate:
		typed.Signature = signature
	}
	return nil
}

func verifyStagingEvidence(evidenceByEdition map[edition.Edition]edition.Evidence, key ed25519.PublicKey, now time.Time, maxAge time.Duration) error {
	if len(evidenceByEdition) != 2 {
		return ErrDenied
	}
	for _, currentEdition := range []edition.Edition{edition.Shared, edition.Dedicated} {
		evidence, ok := evidenceByEdition[currentEdition]
		if !ok || evidence.Edition != currentEdition || !fresh(evidence.IssuedAt, now, maxAge) || edition.VerifyEvidence(evidence, key) != nil {
			return ErrDenied
		}
	}
	return nil
}

func verifyCoreGates(gates []CoreGateEvidence, key ed25519.PublicKey, releaseID, sourceCommit string, now time.Time) error {
	if len(gates) != 6 {
		return ErrDenied
	}
	seen := make(map[string]struct{}, 6)
	for _, evidence := range gates {
		identity := string(evidence.Edition) + ":" + string(evidence.Gate)
		if _, duplicate := seen[identity]; duplicate || evidence.Schema != CoreGateSchema || !validEdition(evidence.Edition) || !validGate(evidence.Gate) || evidence.ReleaseID != releaseID || evidence.SourceCommit != sourceCommit || !digestPattern.MatchString(evidence.PolicyDigest) || evidence.Outcome != "approved" || evidence.IssuedAt.After(now) || !evidence.ExpiresAt.After(now) || !evidence.ExpiresAt.After(evidence.IssuedAt) || !verifySignature(evidence, key, evidence.SignatureAlgorithm, evidence.Signature) {
			return ErrDenied
		}
		seen[identity] = struct{}{}
	}
	for _, currentEdition := range []edition.Edition{edition.Shared, edition.Dedicated} {
		for _, gate := range requiredGates {
			if _, ok := seen[string(currentEdition)+":"+string(gate)]; !ok {
				return ErrDenied
			}
		}
	}
	return nil
}

func validArtifacts(artifacts []Artifact) bool {
	if len(artifacts) == 0 {
		return false
	}
	last := ""
	for _, artifact := range artifacts {
		if artifact.Path == "" || artifact.Path != cleanRelativePath(artifact.Path) || artifact.Path <= last || !digestPattern.MatchString(artifact.Digest) || artifact.SizeBytes <= 0 {
			return false
		}
		last = artifact.Path
	}
	return true
}
func cleanRelativePath(path string) string {
	if path == "" || path[0] == '/' {
		return ""
	}
	parts := regexp.MustCompile(`/+`).Split(path, -1)
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return ""
		}
	}
	return path
}
func validBenchmarkResults(results []BenchmarkResult) bool {
	if len(results) == 0 {
		return false
	}
	last := ""
	for _, result := range results {
		if result.Name == "" || result.Name <= last || result.Iterations <= 0 || result.NanosecondsPerOp <= 0 || result.AllocationsPerOp < 0 || result.BytesPerOp < 0 {
			return false
		}
		last = result.Name
	}
	return true
}
func validReviewScope(scope []string) bool {
	required := []string{"artifact-manifest", "engine", "staging-evidence"}
	if len(scope) != len(required) {
		return false
	}
	for index, value := range required {
		if scope[index] != value {
			return false
		}
	}
	return true
}
func validCertificateDigests(staging, core map[string]string) bool {
	if len(staging) != 2 || len(core) != 6 {
		return false
	}
	for _, current := range []edition.Edition{edition.Shared, edition.Dedicated} {
		if !digestPattern.MatchString(staging[string(current)]) {
			return false
		}
		for _, gate := range requiredGates {
			if !digestPattern.MatchString(core[string(current)+":"+string(gate)]) {
				return false
			}
		}
	}
	return true
}
func validPublicKey(key ed25519.PublicKey) bool { return len(key) == ed25519.PublicKeySize }
func validEdition(value edition.Edition) bool {
	return value == edition.Shared || value == edition.Dedicated
}
func validGate(value Gate) bool {
	return value == GateAdmission || value == GateCertification || value == GateGA
}
func fresh(at, now time.Time, maxAge time.Duration) bool {
	return !at.IsZero() && !at.After(now) && now.Sub(at) <= maxAge
}
func fallback(value string) string {
	if value == "" {
		return "unidentified"
	}
	return value
}

func verifySignature(record any, key ed25519.PublicKey, algorithm, signature string) bool {
	if algorithm != SignatureAlgorithm {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return false
	}
	payload, err := canonical(record)
	return err == nil && ed25519.Verify(key, payload, decoded)
}
func canonical(record any) ([]byte, error) {
	copyRecord, err := copyWithoutSignature(record)
	if err != nil {
		return nil, err
	}
	return json.Marshal(copyRecord)
}
func copyWithoutSignature(record any) (any, error) {
	switch typed := record.(type) {
	case ArtifactManifest:
		typed.Signature = ""
		typed.Artifacts = append([]Artifact(nil), typed.Artifacts...)
		return typed, nil
	case BenchmarkEvidence:
		typed.Signature = ""
		typed.Results = append([]BenchmarkResult(nil), typed.Results...)
		return typed, nil
	case SecurityReview:
		typed.Signature = ""
		typed.Scope = append([]string(nil), typed.Scope...)
		return typed, nil
	case CoreGateEvidence:
		typed.Signature = ""
		return typed, nil
	case Certificate:
		typed.Signature = ""
		typed.StagingEvidenceDigests = copyStringMap(typed.StagingEvidenceDigests)
		typed.CoreGateDigests = copyStringMap(typed.CoreGateDigests)
		return typed, nil
	case *ArtifactManifest:
		if typed == nil {
			return nil, errors.New("nil record")
		}
		return copyWithoutSignature(*typed)
	case *BenchmarkEvidence:
		if typed == nil {
			return nil, errors.New("nil record")
		}
		return copyWithoutSignature(*typed)
	case *SecurityReview:
		if typed == nil {
			return nil, errors.New("nil record")
		}
		return copyWithoutSignature(*typed)
	case *CoreGateEvidence:
		if typed == nil {
			return nil, errors.New("nil record")
		}
		return copyWithoutSignature(*typed)
	case *Certificate:
		if typed == nil {
			return nil, errors.New("nil record")
		}
		return copyWithoutSignature(*typed)
	default:
		return nil, errors.New("unsupported canonical record")
	}
}
func copyStringMap(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
func digestValue(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// Ensure sort remains part of the explicit canonicalization contract. Go JSON
// currently sorts map keys, and the preflight prevents ambiguous slice ordering.
var _ = sort.Strings
