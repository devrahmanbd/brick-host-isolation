// Package isolation creates validated, non-executable Linux isolation plans.
// A future root-owned executor may consume a plan only after it independently
// verifies its digest and enforces the declared controls atomically.
package isolation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/brick/host-isolation/host"
	"github.com/brick/host-isolation/lifecycle"
)

const Schema = "brick.host-isolation.isolation.v1"

var (
	ErrDenied      = errors.New("isolation plan denied")
	ErrUnavailable = errors.New("isolation authority unavailable")
	cageIDPattern  = regexp.MustCompile(`^cage-[a-z0-9][a-z0-9-]{2,62}$`)
	digestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	requiredNS     = []string{"ipc", "mount", "network", "pid", "user", "uts"}
	requiredMounts = map[string]mountRequirement{
		"/":     {source: "baseRoot", readOnly: true, flags: []string{"nodev", "noexec", "nosuid", "readonly"}},
		"/proc": {source: "proc", readOnly: true, flags: []string{"nodev", "noexec", "nosuid"}},
		"/dev":  {source: "minimalDev", readOnly: false, flags: []string{"nodev", "noexec", "nosuid"}},
		"/tmp":  {source: "tmpfs", readOnly: false, flags: []string{"nodev", "noexec", "nosuid"}},
	}
	forbiddenPrefixes = []string{"/opt/brick", "/var/lib/brick", "/run/brick", "/etc/brick", "/root", "/proc/sys", "/proc/kcore", "/sys", "/dev/mem", "/dev/kmem", "/dev/kmsg", "/var/run/docker.sock", "/run/containerd/containerd.sock"}
	allowedDevices    = []string{"null", "random", "urandom", "zero"}
)

type UIDMap struct {
	ContainerID uint32 `json:"containerId"`
	HostID      uint32 `json:"hostId"`
	Size        uint32 `json:"size"`
}

type MountSpec struct {
	SourceKind  string   `json:"sourceKind"`
	Destination string   `json:"destination"`
	ReadOnly    bool     `json:"readOnly"`
	Flags       []string `json:"flags"`
	Options     []string `json:"options"`
}

type mountRequirement struct {
	source   string
	readOnly bool
	flags    []string
}

type Request struct {
	Schema             string            `json:"schema"`
	CageID             string            `json:"cageId"`
	Profile            lifecycle.Profile `json:"profile"`
	BaseRootDigest     string            `json:"baseRootDigest"`
	SeccompDigest      string            `json:"seccompDigest"`
	Namespaces         []string          `json:"namespaces"`
	UIDMappings        []UIDMap          `json:"uidMappings"`
	GIDMappings        []UIDMap          `json:"gidMappings"`
	Mounts             []MountSpec       `json:"mounts"`
	Devices            []string          `json:"devices"`
	NoNewPrivileges    bool              `json:"noNewPrivileges"`
	ClearEnvironment   bool              `json:"clearEnvironment"`
	CloseDescriptorsAt uint32            `json:"closeDescriptorsAt"`
	ParentDeathSignal  string            `json:"parentDeathSignal"`
	InitMode           string            `json:"initMode"`
	WorkingDirectory   string            `json:"workingDirectory"`
	Capabilities       []string          `json:"capabilities"`
}

type Plan struct {
	Schema                string            `json:"schema"`
	CageID                string            `json:"cageId"`
	Profile               lifecycle.Profile `json:"profile"`
	NamespaceFlags        []string          `json:"namespaceFlags"`
	UIDMappings           []UIDMap          `json:"uidMappings"`
	GIDMappings           []UIDMap          `json:"gidMappings"`
	Mounts                []MountSpec       `json:"mounts"`
	Devices               []string          `json:"devices"`
	SeccompDigest         string            `json:"seccompDigest"`
	NoNewPrivileges       bool              `json:"noNewPrivileges"`
	ClearEnvironment      bool              `json:"clearEnvironment"`
	CloseDescriptorsAt    uint32            `json:"closeDescriptorsAt"`
	ParentDeathSignal     string            `json:"parentDeathSignal"`
	InitMode              string            `json:"initMode"`
	WorkingDirectory      string            `json:"workingDirectory"`
	CapabilityBoundingSet []string          `json:"capabilityBoundingSet"`
	PlanDigest            string            `json:"planDigest"`
}

type HostPreflight interface{ Check(context.Context) error }
type AuditSink interface {
	RecordEvent(actor, action, outcome, resource string, metadata map[string]any) error
}

type Authority struct {
	preflight HostPreflight
	audit     AuditSink
}

func NewAuthority(preflight HostPreflight, audit AuditSink) (*Authority, error) {
	if preflight == nil || audit == nil {
		return nil, fmt.Errorf("%w: missing authority dependency", ErrUnavailable)
	}
	return &Authority{preflight: preflight, audit: audit}, nil
}

func (a *Authority) Prepare(ctx context.Context, actor string, request Request) (Plan, error) {
	if a == nil || a.preflight == nil || a.audit == nil {
		return Plan{}, fmt.Errorf("%w: authority dependency unavailable", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return a.deny(actor, request.CageID, "request_cancelled", ErrUnavailable)
	}
	if err := a.preflight.Check(ctx); err != nil {
		return a.deny(actor, request.CageID, "host_preflight_failed", ErrUnavailable)
	}
	if reason := validateRequest(request); reason != "" {
		return a.deny(actor, request.CageID, reason, ErrDenied)
	}
	plan := Plan{Schema: Schema, CageID: request.CageID, Profile: request.Profile, NamespaceFlags: canonicalStrings(request.Namespaces), UIDMappings: canonicalMappings(request.UIDMappings), GIDMappings: canonicalMappings(request.GIDMappings), Mounts: canonicalMounts(request.Mounts), Devices: canonicalStrings(request.Devices), SeccompDigest: request.SeccompDigest, NoNewPrivileges: true, ClearEnvironment: true, CloseDescriptorsAt: 3, ParentDeathSignal: "SIGKILL", InitMode: "supervisedReaper", WorkingDirectory: "/", CapabilityBoundingSet: []string{}}
	digest, err := digestPlan(plan)
	if err != nil {
		return Plan{}, fmt.Errorf("%w: plan serialization failed", ErrUnavailable)
	}
	plan.PlanDigest = digest
	if err := a.audit.RecordEvent(actor, "prepareIsolationPlan", "authorized", request.CageID, map[string]any{"planDigest": plan.PlanDigest, "profile": plan.Profile, "seccompDigest": plan.SeccompDigest}); err != nil {
		return Plan{}, fmt.Errorf("%w: audit sink rejected authorization", ErrUnavailable)
	}
	return plan, nil
}

func (a *Authority) deny(actor, cageID, reason string, result error) (Plan, error) {
	if actor == "" {
		actor = "unidentified"
	}
	if cageID == "" {
		cageID = "unidentified"
	}
	if err := a.audit.RecordEvent(actor, "prepareIsolationPlan", "denied", cageID, map[string]any{"reasonCode": reason}); err != nil {
		return Plan{}, fmt.Errorf("%w: audit sink rejected denial", ErrUnavailable)
	}
	return Plan{}, fmt.Errorf("%w: %s", result, reason)
}

func VerifyPlan(plan Plan) error {
	if reason := validateRequest(Request{Schema: plan.Schema, CageID: plan.CageID, Profile: plan.Profile, SeccompDigest: plan.SeccompDigest, BaseRootDigest: strings.Repeat("0", 64), Namespaces: plan.NamespaceFlags, UIDMappings: plan.UIDMappings, GIDMappings: plan.GIDMappings, Mounts: plan.Mounts, Devices: plan.Devices, NoNewPrivileges: plan.NoNewPrivileges, ClearEnvironment: plan.ClearEnvironment, CloseDescriptorsAt: plan.CloseDescriptorsAt, ParentDeathSignal: plan.ParentDeathSignal, InitMode: plan.InitMode, WorkingDirectory: plan.WorkingDirectory, Capabilities: plan.CapabilityBoundingSet}); reason != "" {
		return fmt.Errorf("%w: %s", ErrDenied, reason)
	}
	digest, err := digestPlan(Plan{Schema: plan.Schema, CageID: plan.CageID, Profile: plan.Profile, NamespaceFlags: canonicalStrings(plan.NamespaceFlags), UIDMappings: canonicalMappings(plan.UIDMappings), GIDMappings: canonicalMappings(plan.GIDMappings), Mounts: canonicalMounts(plan.Mounts), Devices: canonicalStrings(plan.Devices), SeccompDigest: plan.SeccompDigest, NoNewPrivileges: plan.NoNewPrivileges, ClearEnvironment: plan.ClearEnvironment, CloseDescriptorsAt: plan.CloseDescriptorsAt, ParentDeathSignal: plan.ParentDeathSignal, InitMode: plan.InitMode, WorkingDirectory: plan.WorkingDirectory, CapabilityBoundingSet: canonicalStrings(plan.CapabilityBoundingSet)})
	if err != nil || plan.PlanDigest != digest {
		return fmt.Errorf("%w: plan digest mismatch", ErrDenied)
	}
	return nil
}

func validateRequest(request Request) string {
	if request.Schema != Schema || !cageIDPattern.MatchString(request.CageID) || (request.Profile != lifecycle.ProfileSharedTenant && request.Profile != lifecycle.ProfileDedicatedAdministrator) || !digestPattern.MatchString(request.BaseRootDigest) || !digestPattern.MatchString(request.SeccompDigest) {
		return "invalid_isolation_identity"
	}
	if !equalSet(request.Namespaces, requiredNS) || !validMapping(request.UIDMappings) || !validMapping(request.GIDMappings) {
		return "invalid_namespace_or_id_mapping"
	}
	if !request.NoNewPrivileges || !request.ClearEnvironment || request.CloseDescriptorsAt != 3 || request.ParentDeathSignal != "SIGKILL" || request.InitMode != "supervisedReaper" || request.WorkingDirectory != "/" || len(request.Capabilities) != 0 {
		return "invalid_process_controls"
	}
	if !equalSet(request.Devices, allowedDevices) {
		return "invalid_device_policy"
	}
	if reason := validMounts(request.Mounts); reason != "" {
		return reason
	}
	return ""
}

func validMapping(mappings []UIDMap) bool {
	return len(mappings) == 1 && mappings[0].ContainerID == 0 && mappings[0].HostID > 0 && mappings[0].Size == 1
}

func validMounts(mounts []MountSpec) string {
	if len(mounts) != len(requiredMounts) {
		return "incomplete_mount_policy"
	}
	seen := map[string]struct{}{}
	for _, mount := range mounts {
		if !safeDestination(mount.Destination) {
			return "unsafe_mount_destination"
		}
		requirement, ok := requiredMounts[mount.Destination]
		if !ok || mount.SourceKind != requirement.source || mount.ReadOnly != requirement.readOnly || !equalSet(mount.Flags, requirement.flags) || len(mount.Options) == 0 {
			return "invalid_mount_policy"
		}
		if _, exists := seen[mount.Destination]; exists {
			return "duplicate_mount_destination"
		}
		seen[mount.Destination] = struct{}{}
		if mount.Destination == "/proc" && !equalSet(mount.Options, []string{"hidepid=2", "subset=pid"}) {
			return "unsafe_proc_policy"
		}
		if mount.Destination == "/dev" && !equalSet(mount.Options, []string{"mode=0755", "size=16m"}) {
			return "unsafe_device_mount"
		}
		if mount.Destination == "/tmp" && !equalSet(mount.Options, []string{"mode=1777", "size=64m"}) {
			return "unsafe_tmp_mount"
		}
		if mount.Destination == "/" && !equalSet(mount.Options, []string{"privatePropagation"}) {
			return "unsafe_base_root_mount"
		}
	}
	return ""
}

func safeDestination(destination string) bool {
	if destination == "" || !strings.HasPrefix(destination, "/") || path.Clean(destination) != destination || strings.Contains(destination, "//") {
		return false
	}
	for _, forbidden := range forbiddenPrefixes {
		if destination == forbidden || strings.HasPrefix(destination, forbidden+"/") {
			return false
		}
	}
	return true
}

func equalSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	seen := make(map[string]struct{}, len(actual))
	for _, value := range actual {
		if value == "" {
			return false
		}
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

func canonicalStrings(values []string) []string {
	result := make([]string, len(values))
	copy(result, values)
	sort.Strings(result)
	return result
}
func canonicalMappings(values []UIDMap) []UIDMap { return append([]UIDMap(nil), values...) }
func canonicalMounts(values []MountSpec) []MountSpec {
	result := append([]MountSpec(nil), values...)
	for i := range result {
		result[i].Flags = canonicalStrings(result[i].Flags)
		result[i].Options = canonicalStrings(result[i].Options)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Destination < result[j].Destination })
	return result
}
func digestPlan(plan Plan) (string, error) {
	plan.PlanDigest = ""
	encoded, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

var _ HostPreflight = (*host.Preflight)(nil)
