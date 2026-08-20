// Package recovery provides signed, append-oriented event evidence and the
// kill-first recovery orchestration boundary. It deliberately delegates all
// privileged Linux operations to narrow injected interfaces.
package recovery

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/brick/host-isolation/lifecycle"
)

const (
	Schema             = "brick.host-isolation.recovery.v1"
	SignatureAlgorithm = "ed25519"
)

var (
	ErrDenied      = errors.New("host isolation recovery denied")
	ErrUnavailable = errors.New("host isolation recovery unavailable")
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	cagePattern    = regexp.MustCompile(`^cage-[a-z0-9][a-z0-9-]{2,62}$`)
	hostPattern    = regexp.MustCompile(`^host-[a-z0-9][a-z0-9-]{2,62}$`)
	digestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	spiffePattern  = regexp.MustCompile(`^spiffe://[a-z0-9][a-z0-9.-]*/[a-zA-Z0-9._/-]+$`)
	reasonCodes    = map[string]struct{}{"anomaly": {}, "integrityViolation": {}, "policyViolation": {}, "operatorEmergency": {}}
)

type Request struct {
	Schema         string `json:"schema"`
	RecoveryID     string `json:"recoveryId"`
	CageID         string `json:"cageId"`
	CallerSPIFFEID string `json:"callerSpiffeId"`
	HostIdentity   string `json:"hostIdentity"`
	PolicyDigest   string `json:"policyDigest"`
	ReasonCode     string `json:"reasonCode"`
}

// Event contains only redacted metadata and signed evidence identifiers.
type Event struct {
	Schema             string    `json:"schema"`
	EventID            string    `json:"eventId"`
	RecoveryID         string    `json:"recoveryId"`
	CageID             string    `json:"cageId"`
	CallerSPIFFEID     string    `json:"callerSpiffeId"`
	HostIdentity       string    `json:"hostIdentity"`
	PolicyDigest       string    `json:"policyDigest"`
	Sequence           uint64    `json:"sequence"`
	Action             string    `json:"action"`
	Outcome            string    `json:"outcome"`
	ReasonCode         string    `json:"reasonCode"`
	ObservedAt         time.Time `json:"observedAt"`
	EvidenceDigest     string    `json:"evidenceDigest"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	Signature          string    `json:"signature"`
}

type Attestation struct {
	Schema             string    `json:"schema"`
	RecoveryID         string    `json:"recoveryId"`
	CageID             string    `json:"cageId"`
	PolicyDigest       string    `json:"policyDigest"`
	EvidenceDigest     string    `json:"evidenceDigest"`
	FinalSequence      uint64    `json:"finalSequence"`
	Outcome            string    `json:"outcome"`
	IssuedAt           time.Time `json:"issuedAt"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	Signature          string    `json:"signature"`
}

type Journal interface{ Append(Event) error }
type EvidenceStore interface {
	Capture(context.Context, string, string) (string, error)
}

// CageController must operate only on its fixed broker-owned cage identity,
// never policy-provided paths, commands, or shell fragments.
type CageController interface {
	Kill(context.Context, string) error
	Freeze(context.Context, string) error
	WithdrawNetwork(context.Context, string) error
	Destroy(context.Context, string) error
}
type RebuildHandoff interface {
	Handoff(context.Context, string, string) error
}
type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type DecisionError struct{ Code string }

func (e *DecisionError) Error() string        { return ErrDenied.Error() }
func (e *DecisionError) Is(target error) bool { return target == ErrDenied }

type Authority struct {
	key        ed25519.PrivateKey
	journal    Journal
	audit      lifecycle.AuditSink
	evidence   EvidenceStore
	controller CageController
	handoff    RebuildHandoff
	clock      Clock
	sequence   atomic.Uint64
}

func NewAuthority(key ed25519.PrivateKey, journal Journal, audit lifecycle.AuditSink, evidence EvidenceStore, controller CageController, handoff RebuildHandoff, clock Clock) (*Authority, error) {
	if len(key) != ed25519.PrivateKeySize || journal == nil || audit == nil || evidence == nil || controller == nil || handoff == nil || clock == nil {
		return nil, fmt.Errorf("%w: missing recovery authority dependency", ErrUnavailable)
	}
	return &Authority{key: append(ed25519.PrivateKey(nil), key...), journal: journal, audit: audit, evidence: evidence, controller: controller, handoff: handoff, clock: clock}, nil
}

// SuspendAndRecover always kills before freeze, network withdrawal, evidence
// capture, destroy, and clean-rebuild handoff. A failed step prevents later
// side effects and produces a signed failure event where dependencies permit.
func (a *Authority) SuspendAndRecover(ctx context.Context, request Request) (Attestation, error) {
	if a == nil || a.clock == nil || a.journal == nil || a.audit == nil || a.evidence == nil || a.controller == nil || a.handoff == nil {
		return Attestation{}, fmt.Errorf("%w: dependency unavailable", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return Attestation{}, fmt.Errorf("%w: context cancelled", ErrUnavailable)
	}
	if code := validateRequest(request); code != "" {
		return a.denied(request, code)
	}
	if _, err := a.emit(request, "recordRequest", "accepted", "", "accepted"); err != nil {
		return Attestation{}, err
	}
	steps := []struct {
		action string
		run    func() error
	}{
		{"kill", func() error { return a.controller.Kill(ctx, request.CageID) }},
		{"freeze", func() error { return a.controller.Freeze(ctx, request.CageID) }},
		{"withdrawNetwork", func() error { return a.controller.WithdrawNetwork(ctx, request.CageID) }},
	}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return a.failed(request, step.action, "contextCancelled", "")
		}
		if err := step.run(); err != nil {
			return a.failed(request, step.action, "stepFailed", "")
		}
		if _, err := a.emit(request, step.action, "completed", "", "completed"); err != nil {
			return Attestation{}, err
		}
	}
	evidenceDigest, err := a.evidence.Capture(ctx, request.CageID, request.ReasonCode)
	if err != nil || !digestPattern.MatchString(evidenceDigest) {
		return a.failed(request, "captureEvidence", "evidenceUnavailable", "")
	}
	if _, err := a.emit(request, "captureEvidence", "completed", evidenceDigest, "completed"); err != nil {
		return Attestation{}, err
	}
	if err := a.controller.Destroy(ctx, request.CageID); err != nil {
		return a.failed(request, "destroy", "stepFailed", evidenceDigest)
	}
	if _, err := a.emit(request, "destroy", "completed", evidenceDigest, "completed"); err != nil {
		return Attestation{}, err
	}
	if err := a.handoff.Handoff(ctx, request.CageID, evidenceDigest); err != nil {
		return a.failed(request, "cleanRebuildHandoff", "stepFailed", evidenceDigest)
	}
	finalEvent, err := a.emit(request, "cleanRebuildHandoff", "completed", evidenceDigest, "completed")
	if err != nil {
		return Attestation{}, err
	}
	attestation := Attestation{Schema: Schema, RecoveryID: request.RecoveryID, CageID: request.CageID, PolicyDigest: request.PolicyDigest, EvidenceDigest: evidenceDigest, FinalSequence: finalEvent.Sequence, Outcome: "recoveryCompleted", IssuedAt: a.clock.Now().UTC(), SignatureAlgorithm: SignatureAlgorithm}
	if err := SignAttestation(&attestation, a.key); err != nil {
		return Attestation{}, fmt.Errorf("%w: attestation signing failed", ErrUnavailable)
	}
	return attestation, nil
}

func (a *Authority) denied(request Request, code string) (Attestation, error) {
	if _, err := a.emit(request, "recordRequest", "denied", "", code); err != nil {
		return Attestation{}, err
	}
	return Attestation{}, &DecisionError{Code: code}
}
func (a *Authority) failed(request Request, action, code, evidence string) (Attestation, error) {
	if _, err := a.emit(request, action, "failed", evidence, code); err != nil {
		return Attestation{}, err
	}
	return Attestation{}, fmt.Errorf("%w: recovery step failed", ErrUnavailable)
}
func (a *Authority) emit(request Request, action, outcome, evidence, code string) (Event, error) {
	event := Event{Schema: Schema, EventID: request.RecoveryID, RecoveryID: request.RecoveryID, CageID: request.CageID, CallerSPIFFEID: request.CallerSPIFFEID, HostIdentity: request.HostIdentity, PolicyDigest: request.PolicyDigest, Sequence: a.sequence.Add(1), Action: action, Outcome: outcome, ReasonCode: code, ObservedAt: a.clock.Now().UTC(), EvidenceDigest: evidence, SignatureAlgorithm: SignatureAlgorithm}
	if err := SignEvent(&event, a.key); err != nil {
		return Event{}, fmt.Errorf("%w: event signing failed", ErrUnavailable)
	}
	if err := a.journal.Append(event); err != nil {
		return Event{}, fmt.Errorf("%w: event journal unavailable", ErrUnavailable)
	}
	if err := a.audit.RecordEvent(request.CallerSPIFFEID, action, outcome, request.CageID, map[string]any{"recoveryId": request.RecoveryID, "policyDigest": request.PolicyDigest, "reasonCode": code, "sequence": event.Sequence}); err != nil {
		return Event{}, fmt.Errorf("%w: audit sink unavailable", ErrUnavailable)
	}
	return event, nil
}

func SignEvent(event *Event, key ed25519.PrivateKey) error {
	if event == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid event signing input")
	}
	event.SignatureAlgorithm = SignatureAlgorithm
	event.Signature = ""
	payload, err := canonical(event)
	if err != nil {
		return err
	}
	event.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return nil
}
func VerifyEvent(event Event, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize || validateEvent(event) != "" {
		return &DecisionError{Code: "invalid_event"}
	}
	signature, err := base64.RawStdEncoding.DecodeString(event.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return &DecisionError{Code: "invalid_event_signature"}
	}
	payload, err := canonical(&event)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return &DecisionError{Code: "invalid_event_signature"}
	}
	return nil
}
func SignAttestation(value *Attestation, key ed25519.PrivateKey) error {
	if value == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid attestation signing input")
	}
	value.SignatureAlgorithm = SignatureAlgorithm
	value.Signature = ""
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	value.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return nil
}
func VerifyAttestation(value Attestation, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize || value.Schema != Schema || !uuidPattern.MatchString(value.RecoveryID) || !cagePattern.MatchString(value.CageID) || !digestPattern.MatchString(value.PolicyDigest) || !digestPattern.MatchString(value.EvidenceDigest) || value.Outcome != "recoveryCompleted" || value.FinalSequence == 0 || value.SignatureAlgorithm != SignatureAlgorithm {
		return &DecisionError{Code: "invalid_attestation"}
	}
	signature, err := base64.RawStdEncoding.DecodeString(value.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return &DecisionError{Code: "invalid_attestation_signature"}
	}
	value.Signature = ""
	payload, err := json.Marshal(value)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return &DecisionError{Code: "invalid_attestation_signature"}
	}
	return nil
}
func canonical(event *Event) ([]byte, error) {
	copy := *event
	copy.Signature = ""
	return json.Marshal(copy)
}
func validateRequest(value Request) string {
	if value.Schema != Schema || !uuidPattern.MatchString(value.RecoveryID) || !cagePattern.MatchString(value.CageID) || !spiffePattern.MatchString(value.CallerSPIFFEID) || !hostPattern.MatchString(value.HostIdentity) || !digestPattern.MatchString(value.PolicyDigest) {
		return "invalid_request_identity"
	}
	if _, ok := reasonCodes[value.ReasonCode]; !ok {
		return "invalid_reason_code"
	}
	return ""
}
func validateEvent(value Event) string {
	if value.Schema != Schema || value.SignatureAlgorithm != SignatureAlgorithm || !uuidPattern.MatchString(value.EventID) || value.EventID != value.RecoveryID || !cagePattern.MatchString(value.CageID) || !spiffePattern.MatchString(value.CallerSPIFFEID) || !hostPattern.MatchString(value.HostIdentity) || !digestPattern.MatchString(value.PolicyDigest) || value.Sequence == 0 || value.Action == "" || value.Outcome == "" || value.ReasonCode == "" || value.ObservedAt.IsZero() {
		return "invalid_event"
	}
	if value.EvidenceDigest != "" && !digestPattern.MatchString(value.EvidenceDigest) {
		return "invalid_evidence"
	}
	return ""
}
