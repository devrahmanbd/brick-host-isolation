// Package resource authorizes and applies narrowly scoped cgroup v2 control
// files before a workload is admitted. Network outputs are declarative and
// must be consumed by a later private-network namespace executor.
package resource

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
	"strconv"
	"strings"

	"github.com/brick/host-isolation/isolation"
	"github.com/brick/host-isolation/lifecycle"
)

const Schema = "brick.host-isolation.resource.v1"

var (
	ErrDenied       = errors.New("resource policy denied")
	ErrUnavailable  = errors.New("resource authority unavailable")
	cageIDPattern   = regexp.MustCompile(`^cage-[a-z0-9][a-z0-9-]{2,62}$`)
	digestPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	devicePattern   = regexp.MustCompile(`^[0-9]{1,4}:[0-9]{1,6}$`)
	spiffePattern   = regexp.MustCompile(`^spiffe://[a-z0-9][a-z0-9.-]*/[a-zA-Z0-9._/-]+$`)
	hostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

type IOThrottle struct {
	Device    string `json:"device"`
	ReadBPS   uint64 `json:"readBps"`
	WriteBPS  uint64 `json:"writeBps"`
	ReadIOPS  uint64 `json:"readIops"`
	WriteIOPS uint64 `json:"writeIops"`
}

type Endpoint struct {
	ServerName string `json:"serverName"`
	Protocol   string `json:"protocol"`
	Port       uint16 `json:"port"`
}

type NetworkPolicy struct {
	Mode             string     `json:"mode"`
	ProxySPIFFEID    string     `json:"proxySpiffeId"`
	AllowedEndpoints []Endpoint `json:"allowedEndpoints"`
}

type Limits struct {
	CPUQuotaMicros     uint64       `json:"cpuQuotaMicros"`
	CPUPeriodMicros    uint64       `json:"cpuPeriodMicros"`
	MemoryMaxBytes     uint64       `json:"memoryMaxBytes"`
	MemoryHighBytes    uint64       `json:"memoryHighBytes"`
	MemorySwapMaxBytes uint64       `json:"memorySwapMaxBytes"`
	PidsMax            uint64       `json:"pidsMax"`
	IO                 []IOThrottle `json:"io"`
	FileDescriptorMax  uint64       `json:"fileDescriptorMax"`
	WallClockSeconds   uint64       `json:"wallClockSeconds"`
}

type Request struct {
	Schema              string            `json:"schema"`
	CageID              string            `json:"cageId"`
	Profile             lifecycle.Profile `json:"profile"`
	IsolationPlanDigest string            `json:"isolationPlanDigest"`
	Limits              Limits            `json:"limits"`
	Network             NetworkPolicy     `json:"network"`
}

type CgroupPlan struct {
	Path   string                         `json:"path"`
	Writes []struct{ File, Value string } `json:"writes"`
}

type Plan struct {
	Schema              string                                               `json:"schema"`
	CageID              string                                               `json:"cageId"`
	Profile             lifecycle.Profile                                    `json:"profile"`
	IsolationPlanDigest string                                               `json:"isolationPlanDigest"`
	Cgroup              CgroupPlan                                           `json:"cgroup"`
	ExecutorLimits      struct{ FileDescriptorMax, WallClockSeconds uint64 } `json:"executorLimits"`
	Network             NetworkPolicy                                        `json:"network"`
	PlanDigest          string                                               `json:"planDigest"`
}

type AuditSink interface {
	RecordEvent(actor, action, outcome, resource string, metadata map[string]any) error
}
type IsolationVerifier interface{ VerifyPlan(isolation.Plan) error }
type CgroupFS interface {
	Mkdir(path string, mode uint32) error
	WriteFile(path, value string) error
	Remove(path string) error
}

// OSFilesystem is intentionally absent from this package. Production code must
// inject a reviewed root-owned filesystem adapter, keeping all host writes at a
// narrow, testable interface.
type Authority struct {
	root  string
	max   Limits
	audit AuditSink
}

func NewAuthority(brokerCgroupRoot string, maximum Limits, audit AuditSink) (*Authority, error) {
	if audit == nil || !safeCgroupRoot(brokerCgroupRoot) || !validLimits(maximum, maximum) {
		return nil, fmt.Errorf("%w: invalid authority configuration", ErrUnavailable)
	}
	return &Authority{root: brokerCgroupRoot, max: canonicalLimits(maximum), audit: audit}, nil
}

func (a *Authority) Prepare(ctx context.Context, actor string, isolationPlan isolation.Plan, request Request) (Plan, error) {
	if a == nil || a.audit == nil {
		return Plan{}, fmt.Errorf("%w: missing authority dependency", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return a.deny(actor, request.CageID, "request_cancelled", ErrUnavailable)
	}
	if err := isolation.VerifyPlan(isolationPlan); err != nil {
		return a.deny(actor, request.CageID, "unverified_isolation_plan", ErrDenied)
	}
	if reason := a.validate(request, isolationPlan); reason != "" {
		return a.deny(actor, request.CageID, reason, ErrDenied)
	}
	writes := cgroupWrites(request.Limits)
	plan := Plan{Schema: Schema, CageID: request.CageID, Profile: request.Profile, IsolationPlanDigest: request.IsolationPlanDigest, Cgroup: CgroupPlan{Path: path.Join(a.root, request.CageID), Writes: writes}, Network: canonicalNetwork(request.Network)}
	plan.ExecutorLimits.FileDescriptorMax, plan.ExecutorLimits.WallClockSeconds = request.Limits.FileDescriptorMax, request.Limits.WallClockSeconds
	digest, err := digestPlan(plan)
	if err != nil {
		return Plan{}, fmt.Errorf("%w: plan serialization failed", ErrUnavailable)
	}
	plan.PlanDigest = digest
	if err := a.audit.RecordEvent(actor, "prepareResourcePlan", "authorized", request.CageID, map[string]any{"planDigest": plan.PlanDigest, "isolationPlanDigest": plan.IsolationPlanDigest, "networkMode": plan.Network.Mode}); err != nil {
		return Plan{}, fmt.Errorf("%w: audit sink rejected authorization", ErrUnavailable)
	}
	return plan, nil
}

// ApplyCgroup creates only a child under the configured broker subtree and
// writes the complete set of cgroup v2 controller values. It verifies plan
// shape again and removes the empty child after an incomplete write sequence.
func (a *Authority) ApplyCgroup(ctx context.Context, plan Plan, fs CgroupFS) error {
	if a == nil || fs == nil {
		return fmt.Errorf("%w: cgroup dependency unavailable", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: request cancelled", ErrUnavailable)
	}
	if err := a.VerifyPlan(plan); err != nil {
		return err
	}
	if err := fs.Mkdir(plan.Cgroup.Path, 0o750); err != nil {
		return fmt.Errorf("%w: create cgroup", ErrUnavailable)
	}
	completed := false
	defer func() {
		if !completed {
			_ = fs.Remove(plan.Cgroup.Path)
		}
	}()
	for _, write := range plan.Cgroup.Writes {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: request cancelled", ErrUnavailable)
		}
		if err := fs.WriteFile(path.Join(plan.Cgroup.Path, write.File), write.Value); err != nil {
			return fmt.Errorf("%w: write cgroup controller", ErrUnavailable)
		}
	}
	if err := a.audit.RecordEvent("broker", "applyCgroup", "authorized", plan.CageID, map[string]any{"planDigest": plan.PlanDigest, "cgroupPath": plan.Cgroup.Path}); err != nil {
		return fmt.Errorf("%w: audit sink rejected cgroup application", ErrUnavailable)
	}
	completed = true
	return nil
}

func (a *Authority) VerifyPlan(plan Plan) error {
	if plan.Schema != Schema || !cageIDPattern.MatchString(plan.CageID) || !digestPattern.MatchString(plan.IsolationPlanDigest) || !safeCgroupPath(a.root, plan.Cgroup.Path) || plan.Cgroup.Path != path.Join(a.root, plan.CageID) || (plan.Profile != lifecycle.ProfileSharedTenant && plan.Profile != lifecycle.ProfileDedicatedAdministrator) || !validNetwork(plan.Network) || len(plan.Cgroup.Writes) != 6 || plan.ExecutorLimits.FileDescriptorMax == 0 || plan.ExecutorLimits.WallClockSeconds == 0 {
		return fmt.Errorf("%w: invalid resource plan", ErrDenied)
	}
	if !canonicalWrites(plan.Cgroup.Writes) {
		return fmt.Errorf("%w: noncanonical cgroup writes", ErrDenied)
	}
	digest, err := digestPlan(Plan{Schema: plan.Schema, CageID: plan.CageID, Profile: plan.Profile, IsolationPlanDigest: plan.IsolationPlanDigest, Cgroup: plan.Cgroup, ExecutorLimits: plan.ExecutorLimits, Network: canonicalNetwork(plan.Network)})
	if err != nil || digest != plan.PlanDigest {
		return fmt.Errorf("%w: plan digest mismatch", ErrDenied)
	}
	return nil
}

func (a *Authority) validate(request Request, isolationPlan isolation.Plan) string {
	if request.Schema != Schema || !cageIDPattern.MatchString(request.CageID) || request.CageID != isolationPlan.CageID || request.Profile != isolationPlan.Profile || !digestPattern.MatchString(request.IsolationPlanDigest) || request.IsolationPlanDigest != isolationPlan.PlanDigest {
		return "invalid_resource_identity"
	}
	if !contains(isolationPlan.NamespaceFlags, "network") || !isolationPlan.NoNewPrivileges || !isolationPlan.ClearEnvironment || isolationPlan.CloseDescriptorsAt != 3 {
		return "incomplete_isolation_preconditions"
	}
	if !validLimits(request.Limits, a.max) {
		return "invalid_resource_limits"
	}
	if !validNetwork(request.Network) {
		return "invalid_network_policy"
	}
	return ""
}

func (a *Authority) deny(actor, cageID, reason string, result error) (Plan, error) {
	if actor == "" {
		actor = "unidentified"
	}
	if cageID == "" {
		cageID = "unidentified"
	}
	if err := a.audit.RecordEvent(actor, "prepareResourcePlan", "denied", cageID, map[string]any{"reasonCode": reason}); err != nil {
		return Plan{}, fmt.Errorf("%w: audit sink rejected denial", ErrUnavailable)
	}
	return Plan{}, fmt.Errorf("%w: %s", result, reason)
}

func validLimits(actual, maximum Limits) bool {
	if actual.CPUQuotaMicros == 0 || actual.CPUPeriodMicros != 100000 || actual.CPUQuotaMicros > actual.CPUPeriodMicros || actual.MemoryMaxBytes == 0 || actual.MemoryHighBytes == 0 || actual.MemoryHighBytes > actual.MemoryMaxBytes || actual.PidsMax == 0 || actual.FileDescriptorMax == 0 || actual.WallClockSeconds == 0 || len(actual.IO) == 0 {
		return false
	}
	if actual.CPUQuotaMicros > maximum.CPUQuotaMicros || actual.MemoryMaxBytes > maximum.MemoryMaxBytes || actual.MemoryHighBytes > maximum.MemoryHighBytes || actual.MemorySwapMaxBytes > maximum.MemorySwapMaxBytes || actual.PidsMax > maximum.PidsMax || actual.FileDescriptorMax > maximum.FileDescriptorMax || actual.WallClockSeconds > maximum.WallClockSeconds {
		return false
	}
	seen := map[string]struct{}{}
	for _, throttle := range actual.IO {
		if !devicePattern.MatchString(throttle.Device) || throttle.ReadBPS == 0 || throttle.WriteBPS == 0 || throttle.ReadIOPS == 0 || throttle.WriteIOPS == 0 {
			return false
		}
		if _, exists := seen[throttle.Device]; exists {
			return false
		}
		seen[throttle.Device] = struct{}{}
	}
	return true
}

func validNetwork(policy NetworkPolicy) bool {
	if policy.Mode == "denyAll" {
		return policy.ProxySPIFFEID == "" && len(policy.AllowedEndpoints) == 0
	}
	if policy.Mode != "proxyOnly" || !spiffePattern.MatchString(policy.ProxySPIFFEID) || len(policy.AllowedEndpoints) == 0 {
		return false
	}
	seen := map[string]struct{}{}
	for _, endpoint := range policy.AllowedEndpoints {
		if !hostnamePattern.MatchString(endpoint.ServerName) || endpoint.Protocol != "https" || endpoint.Port != 443 {
			return false
		}
		key := endpoint.ServerName + ":" + endpoint.Protocol + ":" + strconv.Itoa(int(endpoint.Port))
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func cgroupWrites(limits Limits) []struct{ File, Value string } {
	io := canonicalIO(limits.IO)
	result := []struct{ File, Value string }{{"cpu.max", strconv.FormatUint(limits.CPUQuotaMicros, 10) + " " + strconv.FormatUint(limits.CPUPeriodMicros, 10)}, {"memory.max", strconv.FormatUint(limits.MemoryMaxBytes, 10)}, {"memory.high", strconv.FormatUint(limits.MemoryHighBytes, 10)}, {"memory.swap.max", strconv.FormatUint(limits.MemorySwapMaxBytes, 10)}, {"pids.max", strconv.FormatUint(limits.PidsMax, 10)}}
	values := make([]string, 0, len(io))
	for _, entry := range io {
		values = append(values, entry.Device+" rbps="+strconv.FormatUint(entry.ReadBPS, 10)+" wbps="+strconv.FormatUint(entry.WriteBPS, 10)+" riops="+strconv.FormatUint(entry.ReadIOPS, 10)+" wiops="+strconv.FormatUint(entry.WriteIOPS, 10))
	}
	result = append(result, struct{ File, Value string }{"io.max", strings.Join(values, "\n")})
	return result
}
func canonicalWrites(writes []struct{ File, Value string }) bool {
	expected := []string{"cpu.max", "memory.max", "memory.high", "memory.swap.max", "pids.max", "io.max"}
	if len(writes) != len(expected) {
		return false
	}
	for i, file := range expected {
		if writes[i].File != file || writes[i].Value == "" {
			return false
		}
	}
	return true
}
func canonicalIO(values []IOThrottle) []IOThrottle {
	result := append([]IOThrottle(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i].Device < result[j].Device })
	return result
}
func canonicalLimits(value Limits) Limits { value.IO = canonicalIO(value.IO); return value }
func canonicalNetwork(policy NetworkPolicy) NetworkPolicy {
	result := policy
	result.AllowedEndpoints = append([]Endpoint(nil), policy.AllowedEndpoints...)
	sort.Slice(result.AllowedEndpoints, func(i, j int) bool {
		if result.AllowedEndpoints[i].ServerName == result.AllowedEndpoints[j].ServerName {
			return result.AllowedEndpoints[i].Protocol < result.AllowedEndpoints[j].Protocol
		}
		return result.AllowedEndpoints[i].ServerName < result.AllowedEndpoints[j].ServerName
	})
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
func safeCgroupRoot(value string) bool { return value == "/sys/fs/cgroup/brick-isolation" }
func safeCgroupPath(root, value string) bool {
	return safeCgroupRoot(root) && strings.HasPrefix(value, root+"/") && path.Clean(value) == value && value != root
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
