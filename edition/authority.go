// Package edition adapts the Shared and Dedicated product profiles to the
// single Brick Host Isolation engine. It creates intent only and never calls
// privileged Linux APIs or bypasses the existing authority chain.
package edition

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

	"github.com/brick/host-isolation/integrity"
	"github.com/brick/host-isolation/isolation"
	"github.com/brick/host-isolation/lifecycle"
	"github.com/brick/host-isolation/resource"
)

const (
	Schema             = "brick.host-isolation.edition.v1"
	SignatureAlgorithm = "ed25519"
)

var (
	ErrDenied         = errors.New("edition profile denied")
	ErrUnavailable    = errors.New("edition authority unavailable")
	digestPattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	evidenceIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	requiredScenarios = []Scenario{"pathTraversal", "mountEscape", "symlinkEscape", "bindMountEscape", "namespaceEscape", "processEscape", "socketExposure", "environmentInjection", "executableInjection", "egressBypass", "resourceExhaustion", "replayAttempt", "auditFailure", "freezeRecovery", "crossTenantIsolation"}
)

type Edition string

const (
	Shared    Edition = "shared"
	Dedicated Edition = "dedicated"
)

type Template struct {
	Profile        lifecycle.Profile
	Limits         resource.Limits
	Network        resource.NetworkPolicy
	ExecutablePath string
	Arguments      []string
}

type Intent struct {
	Schema         string  `json:"schema"`
	Edition        Edition `json:"edition"`
	CageID         string  `json:"cageId"`
	BaseRootDigest string  `json:"baseRootDigest"`
	SeccompDigest  string  `json:"seccompDigest"`
}

// Compilation is an immutable set of inputs for the existing Phase 4, 5 and 6
// authorities. The Edition compiler has no root privileges and no runtime side effects.
type Compilation struct {
	Schema            string                 `json:"schema"`
	Edition           Edition                `json:"edition"`
	Profile           lifecycle.Profile      `json:"profile"`
	CageID            string                 `json:"cageId"`
	IsolationRequest  isolation.Request      `json:"isolationRequest"`
	ResourceTemplate  resource.Limits        `json:"resourceTemplate"`
	NetworkTemplate   resource.NetworkPolicy `json:"networkTemplate"`
	ExecutionTemplate integrity.Request      `json:"executionTemplate"`
	BindingDigest     string                 `json:"bindingDigest"`
}

type ResourcePlanVerifier interface{ VerifyPlan(resource.Plan) error }
type AuditSink interface {
	RecordEvent(actor, action, outcome, resource string, metadata map[string]any) error
}

type Compiler struct {
	templates        map[Edition]Template
	resourceVerifier ResourcePlanVerifier
	audit            AuditSink
}

func NewCompiler(templates map[Edition]Template, resourceVerifier ResourcePlanVerifier, audit AuditSink) (*Compiler, error) {
	if resourceVerifier == nil || audit == nil || len(templates) != 2 {
		return nil, fmt.Errorf("%w: missing compiler dependency", ErrUnavailable)
	}
	copyTemplates := make(map[Edition]Template, len(templates))
	for edition, template := range templates {
		if !validEditionProfile(edition, template.Profile) || !validTemplate(template) {
			return nil, fmt.Errorf("%w: invalid edition template", ErrUnavailable)
		}
		template.Arguments = append([]string(nil), template.Arguments...)
		copyTemplates[edition] = template
	}
	return &Compiler{templates: copyTemplates, resourceVerifier: resourceVerifier, audit: audit}, nil
}

func (c *Compiler) Compile(ctx context.Context, actor string, intent Intent) (Compilation, error) {
	if c == nil || c.resourceVerifier == nil || c.audit == nil {
		return Compilation{}, fmt.Errorf("%w: compiler dependency unavailable", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return c.deny(actor, intent.CageID, "request_cancelled", ErrUnavailable)
	}
	template, exists := c.templates[intent.Edition]
	if intent.Schema != Schema || !exists || !digestPattern.MatchString(intent.BaseRootDigest) || !digestPattern.MatchString(intent.SeccompDigest) {
		return c.deny(actor, intent.CageID, "invalid_edition_intent", ErrDenied)
	}
	request := strictIsolationRequest(intent, template.Profile)
	compilation := Compilation{Schema: Schema, Edition: intent.Edition, Profile: template.Profile, CageID: intent.CageID, IsolationRequest: request, ResourceTemplate: template.Limits, NetworkTemplate: template.Network, ExecutionTemplate: integrity.Request{Schema: integrity.Schema, CageID: intent.CageID, Profile: template.Profile, ExecutablePath: template.ExecutablePath, Arguments: append([]string(nil), template.Arguments...)}}
	digest, err := digestCompilation(compilation)
	if err != nil {
		return Compilation{}, fmt.Errorf("%w: compilation serialization", ErrUnavailable)
	}
	compilation.BindingDigest = digest
	if err := c.audit.RecordEvent(actor, "compileEditionProfile", "authorized", intent.CageID, map[string]any{"edition": intent.Edition, "profile": template.Profile, "bindingDigest": digest}); err != nil {
		return Compilation{}, fmt.Errorf("%w: audit sink rejected authorization", ErrUnavailable)
	}
	return compilation, nil
}

// BindResource prevents a profile compiler from crossing cage, profile, or plan-digest boundaries.
func (c *Compiler) BindResource(ctx context.Context, actor string, compilation Compilation, plan isolation.Plan) (resource.Request, error) {
	if c == nil || c.audit == nil {
		return resource.Request{}, fmt.Errorf("%w: compiler dependency unavailable", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return resource.Request{}, err
	}
	if err := verifyCompilation(compilation); err != nil || isolation.VerifyPlan(plan) != nil || plan.CageID != compilation.CageID || plan.Profile != compilation.Profile {
		return c.denyResource(actor, compilation.CageID, "invalid_isolation_plan_binding")
	}
	request := resource.Request{Schema: resource.Schema, CageID: compilation.CageID, Profile: compilation.Profile, IsolationPlanDigest: plan.PlanDigest, Limits: compilation.ResourceTemplate, Network: compilation.NetworkTemplate}
	if err := c.audit.RecordEvent(actor, "bindEditionResource", "authorized", compilation.CageID, map[string]any{"edition": compilation.Edition, "isolationPlanDigest": plan.PlanDigest}); err != nil {
		return resource.Request{}, fmt.Errorf("%w: audit sink rejected authorization", ErrUnavailable)
	}
	return request, nil
}

func (c *Compiler) BindExecution(ctx context.Context, actor string, compilation Compilation, plan resource.Plan) (integrity.Request, error) {
	if c == nil || c.resourceVerifier == nil || c.audit == nil {
		return integrity.Request{}, fmt.Errorf("%w: compiler dependency unavailable", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return integrity.Request{}, err
	}
	if err := verifyCompilation(compilation); err != nil || c.resourceVerifier.VerifyPlan(plan) != nil || plan.CageID != compilation.CageID || plan.Profile != compilation.Profile {
		return c.denyExecution(actor, compilation.CageID, "invalid_resource_plan_binding")
	}
	request := compilation.ExecutionTemplate
	request.ResourcePlanDigest = plan.PlanDigest
	if err := c.audit.RecordEvent(actor, "bindEditionExecution", "authorized", compilation.CageID, map[string]any{"edition": compilation.Edition, "resourcePlanDigest": plan.PlanDigest}); err != nil {
		return integrity.Request{}, fmt.Errorf("%w: audit sink rejected authorization", ErrUnavailable)
	}
	return request, nil
}

func (c *Compiler) deny(actor, cageID, reason string, result error) (Compilation, error) {
	if err := c.audit.RecordEvent(fallback(actor), "compileEditionProfile", "denied", fallback(cageID), map[string]any{"reasonCode": reason}); err != nil {
		return Compilation{}, fmt.Errorf("%w: audit sink rejected denial", ErrUnavailable)
	}
	return Compilation{}, fmt.Errorf("%w: %s", result, reason)
}
func (c *Compiler) denyResource(actor, cageID, reason string) (resource.Request, error) {
	if err := c.audit.RecordEvent(fallback(actor), "bindEditionResource", "denied", fallback(cageID), map[string]any{"reasonCode": reason}); err != nil {
		return resource.Request{}, fmt.Errorf("%w: audit sink rejected denial", ErrUnavailable)
	}
	return resource.Request{}, fmt.Errorf("%w: %s", ErrDenied, reason)
}
func (c *Compiler) denyExecution(actor, cageID, reason string) (integrity.Request, error) {
	if err := c.audit.RecordEvent(fallback(actor), "bindEditionExecution", "denied", fallback(cageID), map[string]any{"reasonCode": reason}); err != nil {
		return integrity.Request{}, fmt.Errorf("%w: audit sink rejected denial", ErrUnavailable)
	}
	return integrity.Request{}, fmt.Errorf("%w: %s", ErrDenied, reason)
}
func fallback(value string) string {
	if value == "" {
		return "unidentified"
	}
	return value
}

func strictIsolationRequest(intent Intent, profile lifecycle.Profile) isolation.Request {
	return isolation.Request{Schema: isolation.Schema, CageID: intent.CageID, Profile: profile, BaseRootDigest: intent.BaseRootDigest, SeccompDigest: intent.SeccompDigest, Namespaces: []string{"user", "pid", "mount", "ipc", "uts", "network"}, UIDMappings: []isolation.UIDMap{{ContainerID: 0, HostID: 100001, Size: 1}}, GIDMappings: []isolation.UIDMap{{ContainerID: 0, HostID: 100001, Size: 1}}, Mounts: []isolation.MountSpec{{SourceKind: "baseRoot", Destination: "/", ReadOnly: true, Flags: []string{"nodev", "nosuid", "noexec", "readonly"}, Options: []string{"privatePropagation"}}, {SourceKind: "proc", Destination: "/proc", ReadOnly: true, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"hidepid=2", "subset=pid"}}, {SourceKind: "minimalDev", Destination: "/dev", ReadOnly: false, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"mode=0755", "size=16m"}}, {SourceKind: "tmpfs", Destination: "/tmp", ReadOnly: false, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"mode=1777", "size=64m"}}}, Devices: []string{"null", "zero", "random", "urandom"}, NoNewPrivileges: true, ClearEnvironment: true, CloseDescriptorsAt: 3, ParentDeathSignal: "SIGKILL", InitMode: "supervisedReaper", WorkingDirectory: "/", Capabilities: []string{}}
}
func validEditionProfile(edition Edition, profile lifecycle.Profile) bool {
	return (edition == Shared && profile == lifecycle.ProfileSharedTenant) || (edition == Dedicated && profile == lifecycle.ProfileDedicatedAdministrator)
}
func validTemplate(template Template) bool {
	return template.ExecutablePath != "" && len(template.Arguments) > 0 && template.Network.Mode == "denyAll" && template.Limits.CPUQuotaMicros > 0 && template.Limits.CPUPeriodMicros > 0 && template.Limits.MemoryMaxBytes > 0 && template.Limits.PidsMax > 0 && template.Limits.FileDescriptorMax > 0 && template.Limits.WallClockSeconds > 0
}
func verifyCompilation(compilation Compilation) error {
	if compilation.Schema != Schema || !validEditionProfile(compilation.Edition, compilation.Profile) || compilation.BindingDigest == "" {
		return ErrDenied
	}
	digest, err := digestCompilation(Compilation{Schema: compilation.Schema, Edition: compilation.Edition, Profile: compilation.Profile, CageID: compilation.CageID, IsolationRequest: compilation.IsolationRequest, ResourceTemplate: compilation.ResourceTemplate, NetworkTemplate: compilation.NetworkTemplate, ExecutionTemplate: compilation.ExecutionTemplate})
	if err != nil || digest != compilation.BindingDigest {
		return ErrDenied
	}
	return nil
}
func digestCompilation(compilation Compilation) (string, error) {
	compilation.BindingDigest = ""
	encoded, err := json.Marshal(compilation)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

type Scenario string
type Observation struct {
	Scenario       Scenario `json:"scenario"`
	Passed         bool     `json:"passed"`
	EvidenceDigest string   `json:"evidenceDigest"`
}
type Evidence struct {
	Schema             string                 `json:"schema"`
	EvidenceID         string                 `json:"evidenceId"`
	Edition            Edition                `json:"edition"`
	Profile            lifecycle.Profile      `json:"profile"`
	CageID             string                 `json:"cageId"`
	BindingDigest      string                 `json:"bindingDigest"`
	ReleaseBinding     ReleaseEvidenceBinding `json:"releaseBinding"`
	IssuedAt           time.Time              `json:"issuedAt"`
	Observations       []Observation          `json:"observations"`
	SignatureAlgorithm string                 `json:"signatureAlgorithm"`
	Signature          string                 `json:"signature"`
}
type ScenarioRunner interface {
	Run(context.Context, Scenario, Compilation) (Observation, error)
}
type StagingAuthority struct {
	key    ed25519.PrivateKey
	runner ScenarioRunner
	audit  AuditSink
	now    func() time.Time
}

func NewStagingAuthority(key ed25519.PrivateKey, runner ScenarioRunner, audit AuditSink, now func() time.Time) (*StagingAuthority, error) {
	if len(key) != ed25519.PrivateKeySize || runner == nil || audit == nil || now == nil {
		return nil, fmt.Errorf("%w: missing staging dependency", ErrUnavailable)
	}
	return &StagingAuthority{key: append(ed25519.PrivateKey(nil), key...), runner: runner, audit: audit, now: now}, nil
}
func (a *StagingAuthority) Run(ctx context.Context, actor, evidenceID string, compilation Compilation, releaseBinding ReleaseEvidenceBinding) (Evidence, error) {
	if a == nil || a.runner == nil || a.audit == nil || a.now == nil {
		return Evidence{}, fmt.Errorf("%w: staging dependency unavailable", ErrUnavailable)
	}
	if !evidenceIDPattern.MatchString(evidenceID) || verifyCompilation(compilation) != nil || ValidateReleaseEvidenceBinding(releaseBinding) != nil {
		return a.deny(actor, compilation.CageID, "invalid_staging_request")
	}
	observations := make([]Observation, 0, len(requiredScenarios))
	for _, scenario := range requiredScenarios {
		if err := ctx.Err(); err != nil {
			return a.deny(actor, compilation.CageID, "request_cancelled")
		}
		observation, err := a.runner.Run(ctx, scenario, compilation)
		if err != nil || observation.Scenario != scenario || !observation.Passed || !digestPattern.MatchString(observation.EvidenceDigest) {
			return a.deny(actor, compilation.CageID, "staging_scenario_failed")
		}
		observations = append(observations, observation)
	}
	evidence := Evidence{Schema: Schema, EvidenceID: evidenceID, Edition: compilation.Edition, Profile: compilation.Profile, CageID: compilation.CageID, BindingDigest: compilation.BindingDigest, ReleaseBinding: releaseBinding, IssuedAt: a.now().UTC(), Observations: observations, SignatureAlgorithm: SignatureAlgorithm}
	if err := SignEvidence(&evidence, a.key); err != nil {
		return Evidence{}, fmt.Errorf("%w: evidence signing failed", ErrUnavailable)
	}
	if err := a.audit.RecordEvent(actor, "runStagingMatrix", "authorized", compilation.CageID, map[string]any{"edition": compilation.Edition, "evidenceId": evidence.EvidenceID, "bindingDigest": evidence.BindingDigest, "releaseEvidenceBindingDigest": mustReleaseEvidenceBindingDigest(releaseBinding), "candidateReleaseId": releaseBinding.CandidateReleaseID}); err != nil {
		return Evidence{}, fmt.Errorf("%w: audit sink rejected authorization", ErrUnavailable)
	}
	return evidence, nil
}
func (a *StagingAuthority) deny(actor, cageID, reason string) (Evidence, error) {
	if err := a.audit.RecordEvent(fallback(actor), "runStagingMatrix", "denied", fallback(cageID), map[string]any{"reasonCode": reason}); err != nil {
		return Evidence{}, fmt.Errorf("%w: audit sink rejected denial", ErrUnavailable)
	}
	return Evidence{}, fmt.Errorf("%w: %s", ErrDenied, reason)
}
func SignEvidence(evidence *Evidence, key ed25519.PrivateKey) error {
	if evidence == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid evidence signing input")
	}
	evidence.SignatureAlgorithm = SignatureAlgorithm
	evidence.Signature = ""
	payload, err := canonicalEvidence(*evidence)
	if err != nil {
		return err
	}
	evidence.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return nil
}
func VerifyEvidence(evidence Evidence, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize || evidence.Schema != Schema || !evidenceIDPattern.MatchString(evidence.EvidenceID) || !validEditionProfile(evidence.Edition, evidence.Profile) || !digestPattern.MatchString(evidence.BindingDigest) || ValidateReleaseEvidenceBinding(evidence.ReleaseBinding) != nil || evidence.SignatureAlgorithm != SignatureAlgorithm || !validObservations(evidence.Observations) {
		return ErrDenied
	}
	signature, err := base64.RawStdEncoding.DecodeString(evidence.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrDenied
	}
	payload, err := canonicalEvidence(evidence)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return ErrDenied
	}
	return nil
}
func validObservations(observations []Observation) bool {
	if len(observations) != len(requiredScenarios) {
		return false
	}
	for index, scenario := range requiredScenarios {
		if observations[index].Scenario != scenario || !observations[index].Passed || !digestPattern.MatchString(observations[index].EvidenceDigest) {
			return false
		}
	}
	return true
}
func canonicalEvidence(evidence Evidence) ([]byte, error) {
	evidence.Signature = ""
	evidence.Observations = append([]Observation(nil), evidence.Observations...)
	sort.Slice(evidence.Observations, func(i, j int) bool { return evidence.Observations[i].Scenario < evidence.Observations[j].Scenario })
	return json.Marshal(evidence)
}

func mustReleaseEvidenceBindingDigest(binding ReleaseEvidenceBinding) string {
	digest, err := ReleaseEvidenceBindingDigest(binding)
	if err != nil {
		return "unavailable"
	}
	return digest
}
