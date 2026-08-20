// Package integrity turns a signed root-owned executable manifest into a
// deterministic execve plan. It does not execute a program or open host files
// directly; a later root-owned executor must consume the validated plan.
package integrity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/brick/host-isolation/lifecycle"
	"github.com/brick/host-isolation/resource"
)

const (
	Schema             = "brick.host-isolation.integrity.v1"
	SignatureAlgorithm = "ed25519"
)

var (
	ErrDenied      = errors.New("executable integrity denied")
	ErrUnavailable = errors.New("executable integrity unavailable")
	cageIDPattern  = regexp.MustCompile(`^cage-[a-z0-9][a-z0-9-]{2,62}$`)
	digestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	namePattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	valuePattern   = regexp.MustCompile(`^[A-Za-z0-9._/:+-]{1,255}$`)
	allowedEnv     = map[string]struct{}{"HOME": {}, "LANG": {}, "TMPDIR": {}, "TZ": {}}
	forbiddenNames = map[string]struct{}{"CDPATH": {}, "ENV": {}, "GODEBUG": {}, "IFS": {}, "PATH": {}, "SHELLOPTS": {}, "BASHOPTS": {}}
	forbiddenPref  = []string{"LD_", "DYLD_", "PYTHON", "PERL", "RUBY", "NODE_", "BASH", "GCONV", "GIO_"}
)

type Environment struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Dependency struct {
	Path     string `json:"path"`
	Digest   string `json:"digest"`
	OwnerUID uint32 `json:"ownerUid"`
	Mode     uint32 `json:"mode"`
}

type Entry struct {
	Path                string        `json:"path"`
	Digest              string        `json:"digest"`
	OwnerUID            uint32        `json:"ownerUid"`
	Mode                uint32        `json:"mode"`
	Arguments           []string      `json:"arguments"`
	Interpreter         *Dependency   `json:"interpreter,omitempty"`
	RuntimeDependencies []Dependency  `json:"runtimeDependencies"`
	Environment         []Environment `json:"environment"`
}

type Manifest struct {
	Schema             string            `json:"schema"`
	ManifestID         string            `json:"manifestId"`
	Profile            lifecycle.Profile `json:"profile"`
	Entries            []Entry           `json:"entries"`
	SignatureAlgorithm string            `json:"signatureAlgorithm"`
	Signature          string            `json:"signature"`
}

type Request struct {
	Schema               string            `json:"schema"`
	CageID               string            `json:"cageId"`
	Profile              lifecycle.Profile `json:"profile"`
	ResourcePlanDigest   string            `json:"resourcePlanDigest"`
	ExecutablePath       string            `json:"executablePath"`
	Arguments            []string          `json:"arguments"`
	RequestedEnvironment []Environment     `json:"requestedEnvironment"`
}

type FileIdentity struct {
	Digest   string
	OwnerUID uint32
	Mode     uint32
	Regular  bool
	Symlink  bool
}

type ExecPlan struct {
	Schema             string            `json:"schema"`
	CageID             string            `json:"cageId"`
	Profile            lifecycle.Profile `json:"profile"`
	ResourcePlanDigest string            `json:"resourcePlanDigest"`
	ManifestID         string            `json:"manifestId"`
	ManifestDigest     string            `json:"manifestDigest"`
	ExecutablePath     string            `json:"executablePath"`
	InterpreterPath    string            `json:"interpreterPath,omitempty"`
	Arguments          []string          `json:"arguments"`
	Environment        []Environment     `json:"environment"`
	CloseDescriptorsAt uint32            `json:"closeDescriptorsAt"`
	WorkingDirectory   string            `json:"workingDirectory"`
	NoPathLookup       bool              `json:"noPathLookup"`
	PlanDigest         string            `json:"planDigest"`
}

type AuditSink interface {
	RecordEvent(actor, action, outcome, resource string, metadata map[string]any) error
}

type ResourceVerifier interface{ VerifyPlan(resource.Plan) error }
type Inspector interface {
	Inspect(path string) (FileIdentity, error)
}

type Authority struct {
	manifest       Manifest
	manifestDigest string
	resource       ResourceVerifier
	inspector      Inspector
	audit          AuditSink
}

func NewAuthority(manifest Manifest, signer ed25519.PublicKey, resourceVerifier ResourceVerifier, inspector Inspector, audit AuditSink) (*Authority, error) {
	if len(signer) != ed25519.PublicKeySize || resourceVerifier == nil || inspector == nil || audit == nil {
		return nil, fmt.Errorf("%w: missing authority dependency", ErrUnavailable)
	}
	if err := VerifyManifest(manifest, signer); err != nil {
		return nil, fmt.Errorf("%w: manifest verification failed", ErrUnavailable)
	}
	digest, err := digestManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: manifest serialization failed", ErrUnavailable)
	}
	return &Authority{manifest: canonicalManifest(manifest), manifestDigest: digest, resource: resourceVerifier, inspector: inspector, audit: audit}, nil
}

func SignManifest(manifest *Manifest, signer ed25519.PrivateKey) error {
	if manifest == nil || len(signer) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid manifest signing input")
	}
	manifest.SignatureAlgorithm, manifest.Signature = SignatureAlgorithm, ""
	payload, err := canonicalManifestBytes(*manifest)
	if err != nil {
		return err
	}
	manifest.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(signer, payload))
	return nil
}

func VerifyManifest(manifest Manifest, signer ed25519.PublicKey) error {
	if len(signer) != ed25519.PublicKeySize || !validManifest(manifest) || manifest.SignatureAlgorithm != SignatureAlgorithm {
		return fmt.Errorf("%w: invalid manifest", ErrDenied)
	}
	signature, err := base64.RawStdEncoding.DecodeString(manifest.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid manifest signature", ErrDenied)
	}
	payload, err := canonicalManifestBytes(manifest)
	if err != nil || !ed25519.Verify(signer, payload, signature) {
		return fmt.Errorf("%w: invalid manifest signature", ErrDenied)
	}
	return nil
}

func (a *Authority) Prepare(ctx context.Context, actor string, resourcePlan resource.Plan, request Request) (ExecPlan, error) {
	if a == nil || a.resource == nil || a.inspector == nil || a.audit == nil {
		return ExecPlan{}, fmt.Errorf("%w: authority unavailable", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return a.deny(actor, request.CageID, "request_cancelled", ErrUnavailable)
	}
	if err := a.resource.VerifyPlan(resourcePlan); err != nil {
		return a.deny(actor, request.CageID, "unverified_resource_plan", ErrDenied)
	}
	if reason := validateRequest(request, resourcePlan, a.manifest); reason != "" {
		return a.deny(actor, request.CageID, reason, ErrDenied)
	}
	entry := findEntry(a.manifest.Entries, request.ExecutablePath)
	if entry == nil {
		return a.deny(actor, request.CageID, "unknown_executable", ErrDenied)
	}
	if err := a.verifyEntry(*entry); err != nil {
		return a.deny(actor, request.CageID, "executable_integrity_mismatch", ErrDenied)
	}
	if entry.Interpreter != nil {
		if err := a.verifyDependency(*entry.Interpreter); err != nil {
			return a.deny(actor, request.CageID, "interpreter_integrity_mismatch", ErrDenied)
		}
	}
	for _, dependency := range entry.RuntimeDependencies {
		if err := a.verifyDependency(dependency); err != nil {
			return a.deny(actor, request.CageID, "runtime_dependency_mismatch", ErrDenied)
		}
	}
	plan := ExecPlan{Schema: Schema, CageID: request.CageID, Profile: request.Profile, ResourcePlanDigest: request.ResourcePlanDigest, ManifestID: a.manifest.ManifestID, ManifestDigest: a.manifestDigest, ExecutablePath: entry.Path, Arguments: append([]string(nil), entry.Arguments...), Environment: canonicalEnvironment(entry.Environment), CloseDescriptorsAt: 3, WorkingDirectory: "/", NoPathLookup: true}
	if entry.Interpreter != nil {
		plan.InterpreterPath = entry.Interpreter.Path
	}
	digest, err := digestExecPlan(plan)
	if err != nil {
		return ExecPlan{}, fmt.Errorf("%w: execution plan serialization failed", ErrUnavailable)
	}
	plan.PlanDigest = digest
	if err := a.audit.RecordEvent(actorOrUnknown(actor), "prepareExecPlan", "authorized", request.CageID, map[string]any{"planDigest": plan.PlanDigest, "manifestDigest": plan.ManifestDigest, "resourcePlanDigest": plan.ResourcePlanDigest}); err != nil {
		return ExecPlan{}, fmt.Errorf("%w: audit sink rejected authorization", ErrUnavailable)
	}
	return plan, nil
}

func (a *Authority) VerifyPlan(plan ExecPlan) error {
	if a == nil || plan.Schema != Schema || !cageIDPattern.MatchString(plan.CageID) || plan.Profile != a.manifest.Profile || !digestPattern.MatchString(plan.ResourcePlanDigest) || plan.ManifestID != a.manifest.ManifestID || plan.ManifestDigest != a.manifestDigest || plan.CloseDescriptorsAt != 3 || plan.WorkingDirectory != "/" || !plan.NoPathLookup {
		return fmt.Errorf("%w: invalid exec plan", ErrDenied)
	}
	entry := findEntry(a.manifest.Entries, plan.ExecutablePath)
	if entry == nil || !equalStrings(entry.Arguments, plan.Arguments) || !equalEnvironment(canonicalEnvironment(entry.Environment), plan.Environment) {
		return fmt.Errorf("%w: exec plan manifest mismatch", ErrDenied)
	}
	interpreter := ""
	if entry.Interpreter != nil {
		interpreter = entry.Interpreter.Path
	}
	if plan.InterpreterPath != interpreter {
		return fmt.Errorf("%w: exec plan interpreter mismatch", ErrDenied)
	}
	digest, err := digestExecPlan(ExecPlan{Schema: plan.Schema, CageID: plan.CageID, Profile: plan.Profile, ResourcePlanDigest: plan.ResourcePlanDigest, ManifestID: plan.ManifestID, ManifestDigest: plan.ManifestDigest, ExecutablePath: plan.ExecutablePath, InterpreterPath: plan.InterpreterPath, Arguments: append([]string(nil), plan.Arguments...), Environment: canonicalEnvironment(plan.Environment), CloseDescriptorsAt: plan.CloseDescriptorsAt, WorkingDirectory: plan.WorkingDirectory, NoPathLookup: plan.NoPathLookup})
	if err != nil || digest != plan.PlanDigest {
		return fmt.Errorf("%w: exec plan digest mismatch", ErrDenied)
	}
	return nil
}

func (a *Authority) verifyEntry(entry Entry) error {
	identity, err := a.inspector.Inspect(entry.Path)
	if err != nil || !identity.Regular || identity.Symlink || identity.Digest != entry.Digest || identity.OwnerUID != entry.OwnerUID || identity.Mode != entry.Mode {
		return errors.New("unsafe executable")
	}
	return nil
}
func (a *Authority) verifyDependency(dependency Dependency) error {
	identity, err := a.inspector.Inspect(dependency.Path)
	if err != nil || !identity.Regular || identity.Symlink || identity.Digest != dependency.Digest || identity.OwnerUID != dependency.OwnerUID || identity.Mode != dependency.Mode {
		return errors.New("unsafe dependency")
	}
	return nil
}
func (a *Authority) deny(actor, cageID, reason string, outcome error) (ExecPlan, error) {
	if cageID == "" {
		cageID = "unidentified"
	}
	if err := a.audit.RecordEvent(actorOrUnknown(actor), "prepareExecPlan", "denied", cageID, map[string]any{"reasonCode": reason}); err != nil {
		return ExecPlan{}, fmt.Errorf("%w: audit sink rejected denial", ErrUnavailable)
	}
	return ExecPlan{}, fmt.Errorf("%w: %s", outcome, reason)
}

func validManifest(manifest Manifest) bool {
	if manifest.Schema != Schema || manifest.ManifestID == "" || !validProfile(manifest.Profile) || len(manifest.Entries) == 0 {
		return false
	}
	seen := map[string]struct{}{}
	for _, entry := range manifest.Entries {
		if _, exists := seen[entry.Path]; exists || !validEntry(entry) {
			return false
		}
		seen[entry.Path] = struct{}{}
	}
	return true
}
func validEntry(entry Entry) bool {
	if !safeExecutablePath(entry.Path) || !digestPattern.MatchString(entry.Digest) || entry.OwnerUID != 0 || entry.Mode != 0o755 || !validArguments(entry.Arguments) || !validEnvironment(entry.Environment) {
		return false
	}
	if entry.Interpreter != nil && !validDependency(*entry.Interpreter) {
		return false
	}
	seen := map[string]struct{}{}
	for _, dependency := range entry.RuntimeDependencies {
		if _, exists := seen[dependency.Path]; exists || !validDependency(dependency) {
			return false
		}
		seen[dependency.Path] = struct{}{}
	}
	return true
}
func validDependency(dependency Dependency) bool {
	return safeRuntimePath(dependency.Path) && digestPattern.MatchString(dependency.Digest) && dependency.OwnerUID == 0 && (dependency.Mode == 0o755 || dependency.Mode == 0o644)
}
func validateRequest(request Request, plan resource.Plan, manifest Manifest) string {
	if request.Schema != Schema || !cageIDPattern.MatchString(request.CageID) || request.CageID != plan.CageID || request.Profile != manifest.Profile || request.Profile != plan.Profile || !digestPattern.MatchString(request.ResourcePlanDigest) || request.ResourcePlanDigest != plan.PlanDigest {
		return "invalid_request_binding"
	}
	if !safeExecutablePath(request.ExecutablePath) || !validArguments(request.Arguments) || len(request.RequestedEnvironment) != 0 {
		return "unsafe_execution_request"
	}
	entry := findEntry(manifest.Entries, request.ExecutablePath)
	if entry == nil || !equalStrings(entry.Arguments, request.Arguments) {
		return "unapproved_executable_or_arguments"
	}
	return ""
}
func safeExecutablePath(value string) bool {
	return (strings.HasPrefix(value, "/runtime/bin/") || strings.HasPrefix(value, "/runtime/interpreters/")) && path.Clean(value) == value && !strings.Contains(value, "//") && !strings.Contains(value, "..")
}
func safeRuntimePath(value string) bool {
	return (strings.HasPrefix(value, "/runtime/lib/") || strings.HasPrefix(value, "/runtime/interpreters/") || strings.HasPrefix(value, "/runtime/bin/")) && path.Clean(value) == value && !strings.Contains(value, "//") && !strings.Contains(value, "..")
}
func validArguments(arguments []string) bool {
	if len(arguments) > 32 {
		return false
	}
	for _, argument := range arguments {
		if argument == "" || len(argument) > 512 || strings.ContainsAny(argument, "\x00\r\n") {
			return false
		}
	}
	return true
}
func validEnvironment(environment []Environment) bool {
	if len(environment) > 4 {
		return false
	}
	seen := map[string]struct{}{}
	for _, item := range environment {
		if _, exists := seen[item.Name]; exists || !safeEnvironment(item) {
			return false
		}
		seen[item.Name] = struct{}{}
	}
	return true
}
func safeEnvironment(item Environment) bool {
	if !namePattern.MatchString(item.Name) || !valuePattern.MatchString(item.Value) {
		return false
	}
	if _, forbidden := forbiddenNames[item.Name]; forbidden {
		return false
	}
	for _, prefix := range forbiddenPref {
		if strings.HasPrefix(item.Name, prefix) {
			return false
		}
	}
	if _, allowed := allowedEnv[item.Name]; !allowed {
		return false
	}
	switch item.Name {
	case "HOME":
		return item.Value == "/nonexistent"
	case "TMPDIR":
		return item.Value == "/tmp"
	case "TZ":
		return item.Value == "UTC"
	case "LANG":
		return item.Value == "C" || item.Value == "C.UTF-8"
	}
	return false
}
func validProfile(profile lifecycle.Profile) bool {
	return profile == lifecycle.ProfileSharedTenant || profile == lifecycle.ProfileDedicatedAdministrator
}
func findEntry(entries []Entry, executable string) *Entry {
	for index := range entries {
		if entries[index].Path == executable {
			return &entries[index]
		}
	}
	return nil
}
func canonicalManifest(manifest Manifest) Manifest {
	manifest.Signature = ""
	manifest.Entries = append([]Entry(nil), manifest.Entries...)
	sort.Slice(manifest.Entries, func(i, j int) bool { return manifest.Entries[i].Path < manifest.Entries[j].Path })
	for index := range manifest.Entries {
		manifest.Entries[index].Arguments = append([]string(nil), manifest.Entries[index].Arguments...)
		manifest.Entries[index].Environment = canonicalEnvironment(manifest.Entries[index].Environment)
		manifest.Entries[index].RuntimeDependencies = append([]Dependency(nil), manifest.Entries[index].RuntimeDependencies...)
		sort.Slice(manifest.Entries[index].RuntimeDependencies, func(i, j int) bool {
			return manifest.Entries[index].RuntimeDependencies[i].Path < manifest.Entries[index].RuntimeDependencies[j].Path
		})
	}
	return manifest
}
func canonicalManifestBytes(manifest Manifest) ([]byte, error) {
	return json.Marshal(canonicalManifest(manifest))
}
func digestManifest(manifest Manifest) (string, error) {
	data, err := canonicalManifestBytes(manifest)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func canonicalEnvironment(environment []Environment) []Environment {
	result := append([]Environment(nil), environment...)
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
func equalEnvironment(left, right []Environment) bool {
	left, right = canonicalEnvironment(left), canonicalEnvironment(right)
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
func digestExecPlan(plan ExecPlan) (string, error) {
	plan.PlanDigest = ""
	plan.Arguments = append([]string(nil), plan.Arguments...)
	plan.Environment = canonicalEnvironment(plan.Environment)
	data, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func actorOrUnknown(actor string) string {
	if actor == "" {
		return "unidentified"
	}
	return actor
}
