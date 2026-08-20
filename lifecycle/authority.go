// Package lifecycle implements the fail-closed, signed request boundary for
// Brick Host Isolation. It authorizes lifecycle intent only; Linux host
// enforcement is deliberately deferred to later phases.
package lifecycle

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const (
	Schema                 = "brick.host-isolation.v1"
	SignatureAlgorithm     = "ed25519"
	maxRequestValidity     = 15 * time.Minute
	maxClockSkew           = 2 * time.Minute
	maxAttestationValidity = 10 * time.Minute
)

var (
	ErrDenied          = errors.New("host isolation request denied")
	ErrUnavailable     = errors.New("host isolation authority unavailable")
	requestIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	cageIDPattern      = regexp.MustCompile(`^cage-[a-z0-9][a-z0-9-]{2,62}$`)
	policyIDPattern    = regexp.MustCompile(`^policy-[a-z0-9][a-z0-9-]{2,62}$`)
	hostIDPattern      = regexp.MustCompile(`^host-[a-z0-9][a-z0-9-]{2,62}$`)
	digestPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	mandatoryLayers    = []string{"auditBeforeResponse", "callerAuthentication", "capabilityDrop", "cgroupV2", "defaultDenyEgress", "environmentSanitization", "executableManifest", "immutableBaseRoot", "ipcNamespace", "mountNamespace", "networkNamespace", "noNewPrivileges", "pidNamespace", "protectedPathExclusion", "replayProtection", "seccomp", "userNamespace", "utsNamespace"}
	protectedHostPaths = []string{"/opt/brick", "/var/lib/brick", "/run/brick", "/etc/brick", "/root", "/var/run/docker.sock", "/run/containerd/containerd.sock"}
)

type Action string

const (
	ActionCreate   Action = "create"
	ActionActivate Action = "activate"
	ActionSuspend  Action = "suspend"
	ActionDestroy  Action = "destroy"
	ActionAttest   Action = "attest"
)

type Profile string

const (
	ProfileSharedTenant           Profile = "sharedTenant"
	ProfileDedicatedAdministrator Profile = "dedicatedAdministrator"
)

// Request is a signed lifecycle-intent envelope. No field may be inferred by
// the authority: callers bind every security-relevant value explicitly.
type Request struct {
	Schema                   string         `json:"schema"`
	RequestID                string         `json:"requestId"`
	Action                   Action         `json:"action"`
	IssuedAt                 time.Time      `json:"issuedAt"`
	ExpiresAt                time.Time      `json:"expiresAt"`
	CallerSPIFFEID           string         `json:"callerSpiffeId"`
	PolicyID                 string         `json:"policyId"`
	PolicyDigest             string         `json:"policyDigest"`
	Profile                  Profile        `json:"profile"`
	CageID                   string         `json:"cageId"`
	HostIdentity             string         `json:"hostIdentity"`
	ResourcePolicy           ResourcePolicy `json:"resourcePolicy"`
	MountPolicy              MountPolicy    `json:"mountPolicy"`
	NetworkPolicy            NetworkPolicy  `json:"networkPolicy"`
	ExecutableManifestDigest string         `json:"executableManifestDigest"`
	AuditTarget              string         `json:"auditTarget"`
	SignatureAlgorithm       string         `json:"signatureAlgorithm"`
	Signature                string         `json:"signature"`
}

type ResourcePolicy struct {
	CPUQuotaMilli  int64 `json:"cpuQuotaMilli"`
	MemoryMaxBytes int64 `json:"memoryMaxBytes"`
	PidsMax        int64 `json:"pidsMax"`
	IOWeight       int64 `json:"ioWeight"`
}

type MountPolicy struct {
	BaseRoot        string   `json:"baseRoot"`
	Mounts          []Mount  `json:"mounts"`
	MandatoryLayers []string `json:"mandatoryLayers"`
}

type Mount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"readOnly"`
}

type NetworkPolicy struct {
	Mode             string   `json:"mode"`
	AllowedEndpoints []string `json:"allowedEndpoints"`
}

// Attestation is a minimal, signed evidence envelope. It intentionally omits
// mount paths, command data, and other host-internal policy material.
type Attestation struct {
	Schema              string    `json:"schema"`
	AttestationID       string    `json:"attestationId"`
	RequestID           string    `json:"requestId"`
	CageID              string    `json:"cageId"`
	Profile             Profile   `json:"profile"`
	HostIdentity        string    `json:"hostIdentity"`
	PolicyDigest        string    `json:"policyDigest"`
	EngineReleaseDigest string    `json:"engineReleaseDigest"`
	EnforcementDigest   string    `json:"enforcementDigest"`
	IssuedAt            time.Time `json:"issuedAt"`
	ExpiresAt           time.Time `json:"expiresAt"`
	MonotonicSequence   uint64    `json:"monotonicSequence"`
	Outcome             string    `json:"outcome"`
	SignatureAlgorithm  string    `json:"signatureAlgorithm"`
	Signature           string    `json:"signature"`
}

// AuditSink must durably record every decision. Failure to audit fails closed.
type AuditSink interface {
	RecordEvent(actor, action, outcome, resource string, metadata map[string]any) error
}

// ReplayLedger atomically claims a request identifier until its expiry. A
// non-durable or unavailable ledger is not an acceptable implementation.
type ReplayLedger interface {
	Claim(requestID string, expiresAt time.Time) (claimed bool, err error)
}

type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// DecisionError exposes a stable reason code without returning sensitive
// policy values, host paths, signatures, or key material to callers.
type DecisionError struct{ Code string }

func (e *DecisionError) Error() string { return ErrDenied.Error() }

func (e *DecisionError) Is(target error) bool { return target == ErrDenied }

// Authority verifies signed lifecycle intent and signs minimal attestations.
// It does not activate host resources; later phases may call it before any
// privileged lifecycle side effect.
type Authority struct {
	engineKey           ed25519.PrivateKey
	engineReleaseDigest string
	trustedCallers      map[string]ed25519.PublicKey
	audit               AuditSink
	replay              ReplayLedger
	clock               Clock
	sequence            atomic.Uint64
}

func NewAuthority(engineKey ed25519.PrivateKey, engineReleaseDigest string, trustedCallers map[string]ed25519.PublicKey, audit AuditSink, replay ReplayLedger, clock Clock) (*Authority, error) {
	if len(engineKey) != ed25519.PrivateKeySize || !digestPattern.MatchString(engineReleaseDigest) {
		return nil, fmt.Errorf("%w: invalid engine signing configuration", ErrUnavailable)
	}
	if audit == nil || replay == nil || clock == nil || len(trustedCallers) == 0 {
		return nil, fmt.Errorf("%w: missing required authority dependency", ErrUnavailable)
	}
	copyKeys := make(map[string]ed25519.PublicKey, len(trustedCallers))
	for id, key := range trustedCallers {
		if !validSPIFFEID(id) || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: invalid trusted caller configuration", ErrUnavailable)
		}
		copyKeys[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &Authority{engineKey: append(ed25519.PrivateKey(nil), engineKey...), engineReleaseDigest: engineReleaseDigest, trustedCallers: copyKeys, audit: audit, replay: replay, clock: clock}, nil
}

// Authorize validates and records a lifecycle request, then returns signed
// authorization evidence. It fails closed on every ambiguous dependency.
func (a *Authority) Authorize(req Request) (Attestation, error) {
	if a == nil || a.clock == nil || a.audit == nil || a.replay == nil {
		return Attestation{}, fmt.Errorf("%w: authority dependency unavailable", ErrUnavailable)
	}
	now := a.clock.Now().UTC()
	if code := validateRequestShape(req, now); code != "" {
		return a.deny(req, code)
	}
	key, ok := a.trustedCallers[req.CallerSPIFFEID]
	if !ok {
		return a.deny(req, "unknown_caller_identity")
	}
	signature, err := base64.RawStdEncoding.DecodeString(req.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return a.deny(req, "invalid_signature_encoding")
	}
	payload, err := canonicalRequest(req)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return a.deny(req, "invalid_request_signature")
	}
	claimed, err := a.replay.Claim(req.RequestID, req.ExpiresAt)
	if err != nil {
		return a.deny(req, "replay_ledger_unavailable")
	}
	if !claimed {
		return a.deny(req, "replayed_request")
	}
	attestation := Attestation{
		Schema:              Schema,
		AttestationID:       req.RequestID,
		RequestID:           req.RequestID,
		CageID:              req.CageID,
		Profile:             req.Profile,
		HostIdentity:        req.HostIdentity,
		PolicyDigest:        req.PolicyDigest,
		EngineReleaseDigest: a.engineReleaseDigest,
		EnforcementDigest:   req.ExecutableManifestDigest,
		IssuedAt:            now,
		ExpiresAt:           minTime(req.ExpiresAt, now.Add(maxAttestationValidity)),
		MonotonicSequence:   a.sequence.Add(1),
		Outcome:             "authorized",
		SignatureAlgorithm:  SignatureAlgorithm,
	}
	if err := SignAttestation(&attestation, a.engineKey); err != nil {
		return Attestation{}, fmt.Errorf("%w: unable to sign attestation", ErrUnavailable)
	}
	if err := a.audit.RecordEvent(req.CallerSPIFFEID, string(req.Action), "authorized", req.CageID, auditMetadata(req, "authorized")); err != nil {
		return Attestation{}, fmt.Errorf("%w: audit sink rejected authorization", ErrUnavailable)
	}
	return attestation, nil
}

func (a *Authority) deny(req Request, code string) (Attestation, error) {
	actor := req.CallerSPIFFEID
	if actor == "" {
		actor = "unidentified"
	}
	resource := req.CageID
	if resource == "" {
		resource = "unidentified"
	}
	if err := a.audit.RecordEvent(actor, string(req.Action), "denied", resource, auditMetadata(req, code)); err != nil {
		return Attestation{}, fmt.Errorf("%w: audit sink rejected denial", ErrUnavailable)
	}
	return Attestation{}, &DecisionError{Code: code}
}

func auditMetadata(req Request, outcome string) map[string]any {
	return map[string]any{"requestId": req.RequestID, "policyDigest": req.PolicyDigest, "profile": req.Profile, "reasonCode": outcome}
}

func SignRequest(req *Request, key ed25519.PrivateKey) error {
	if req == nil || len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid request signing input")
	}
	req.SignatureAlgorithm = SignatureAlgorithm
	req.Signature = ""
	payload, err := canonicalRequest(*req)
	if err != nil {
		return err
	}
	req.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return nil
}

func SignAttestation(attestation *Attestation, key ed25519.PrivateKey) error {
	if attestation == nil || len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid attestation signing input")
	}
	attestation.SignatureAlgorithm = SignatureAlgorithm
	attestation.Signature = ""
	payload, err := canonicalAttestation(*attestation)
	if err != nil {
		return err
	}
	attestation.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return nil
}

func VerifyAttestation(attestation Attestation, key ed25519.PublicKey, now time.Time) error {
	if len(key) != ed25519.PublicKeySize || attestation.Schema != Schema || attestation.SignatureAlgorithm != SignatureAlgorithm || !requestIDPattern.MatchString(attestation.AttestationID) || attestation.AttestationID != attestation.RequestID || !cageIDPattern.MatchString(attestation.CageID) || !hostIDPattern.MatchString(attestation.HostIdentity) || !digestPattern.MatchString(attestation.PolicyDigest) || !digestPattern.MatchString(attestation.EngineReleaseDigest) || !digestPattern.MatchString(attestation.EnforcementDigest) || attestation.Outcome != "authorized" || !attestation.ExpiresAt.After(now.UTC()) || !attestation.ExpiresAt.After(attestation.IssuedAt) {
		return &DecisionError{Code: "invalid_attestation"}
	}
	signature, err := base64.RawStdEncoding.DecodeString(attestation.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return &DecisionError{Code: "invalid_attestation_signature"}
	}
	payload, err := canonicalAttestation(attestation)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return &DecisionError{Code: "invalid_attestation_signature"}
	}
	return nil
}

func validateRequestShape(req Request, now time.Time) string {
	if req.Schema != Schema || req.SignatureAlgorithm != SignatureAlgorithm || !requestIDPattern.MatchString(req.RequestID) || !validAction(req.Action) || !validSPIFFEID(req.CallerSPIFFEID) || !policyIDPattern.MatchString(req.PolicyID) || !digestPattern.MatchString(req.PolicyDigest) || !validProfile(req.Profile) || !cageIDPattern.MatchString(req.CageID) || !hostIDPattern.MatchString(req.HostIdentity) || !digestPattern.MatchString(req.ExecutableManifestDigest) {
		return "invalid_request_identity"
	}
	if req.IssuedAt.IsZero() || req.ExpiresAt.IsZero() || !req.ExpiresAt.After(req.IssuedAt) || req.ExpiresAt.Sub(req.IssuedAt) > maxRequestValidity || req.IssuedAt.After(now.Add(maxClockSkew)) || !req.ExpiresAt.After(now) {
		return "invalid_request_time_window"
	}
	if req.ResourcePolicy.CPUQuotaMilli <= 0 || req.ResourcePolicy.MemoryMaxBytes <= 0 || req.ResourcePolicy.PidsMax <= 0 || req.ResourcePolicy.IOWeight < 1 || req.ResourcePolicy.IOWeight > 10000 {
		return "invalid_resource_policy"
	}
	if code := validateMountPolicy(req.MountPolicy); code != "" {
		return code
	}
	if code := validateNetworkPolicy(req.NetworkPolicy); code != "" {
		return code
	}
	auditURL, err := url.ParseRequestURI(req.AuditTarget)
	if err != nil || auditURL.Scheme != "audit" || auditURL.Host == "" || auditURL.User != nil || auditURL.RawQuery != "" || auditURL.Fragment != "" {
		return "invalid_audit_target"
	}
	return ""
}

func validateMountPolicy(policy MountPolicy) string {
	if !safeAbsolutePath(policy.BaseRoot) || protectedPath(policy.BaseRoot) || !equalStringSet(policy.MandatoryLayers, mandatoryLayers) {
		return "invalid_mount_policy"
	}
	seenDestinations := map[string]struct{}{}
	for _, mount := range policy.Mounts {
		if !safeAbsolutePath(mount.Source) || !safeAbsolutePath(mount.Destination) || protectedPath(mount.Source) || protectedPath(mount.Destination) || !mount.ReadOnly {
			return "unsafe_mount_policy"
		}
		if _, exists := seenDestinations[mount.Destination]; exists {
			return "duplicate_mount_destination"
		}
		seenDestinations[mount.Destination] = struct{}{}
	}
	return ""
}

func validateNetworkPolicy(policy NetworkPolicy) string {
	if policy.Mode != "defaultDeny" {
		return "invalid_network_mode"
	}
	seen := map[string]struct{}{}
	for _, endpoint := range policy.AllowedEndpoints {
		u, err := url.ParseRequestURI(endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return "invalid_egress_endpoint"
		}
		if _, exists := seen[endpoint]; exists {
			return "duplicate_egress_endpoint"
		}
		seen[endpoint] = struct{}{}
	}
	return ""
}

func canonicalRequest(req Request) ([]byte, error) {
	req.Signature = ""
	req.MountPolicy.MandatoryLayers = append([]string(nil), req.MountPolicy.MandatoryLayers...)
	sort.Strings(req.MountPolicy.MandatoryLayers)
	req.MountPolicy.Mounts = append([]Mount(nil), req.MountPolicy.Mounts...)
	sort.Slice(req.MountPolicy.Mounts, func(i, j int) bool {
		if req.MountPolicy.Mounts[i].Destination == req.MountPolicy.Mounts[j].Destination {
			return req.MountPolicy.Mounts[i].Source < req.MountPolicy.Mounts[j].Source
		}
		return req.MountPolicy.Mounts[i].Destination < req.MountPolicy.Mounts[j].Destination
	})
	req.NetworkPolicy.AllowedEndpoints = append([]string(nil), req.NetworkPolicy.AllowedEndpoints...)
	sort.Strings(req.NetworkPolicy.AllowedEndpoints)
	return json.Marshal(req)
}

func canonicalAttestation(attestation Attestation) ([]byte, error) {
	attestation.Signature = ""
	return json.Marshal(attestation)
}

func validAction(action Action) bool {
	return action == ActionCreate || action == ActionActivate || action == ActionSuspend || action == ActionDestroy || action == ActionAttest
}

func validProfile(profile Profile) bool {
	return profile == ProfileSharedTenant || profile == ProfileDedicatedAdministrator
}

func validSPIFFEID(value string) bool {
	u, err := url.ParseRequestURI(value)
	return err == nil && u.Scheme == "spiffe" && u.Host != "" && strings.HasPrefix(u.Path, "/") && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

func safeAbsolutePath(value string) bool {
	return strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "/" && !strings.Contains(value, "//")
}

func protectedPath(value string) bool {
	for _, protected := range protectedHostPaths {
		if value == protected || strings.HasPrefix(value, protected+"/") {
			return true
		}
	}
	return false
}

func equalStringSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	seen := make(map[string]struct{}, len(actual))
	for _, value := range actual {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	for _, value := range expected {
		if _, exists := seen[value]; !exists {
			return false
		}
	}
	return true
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
