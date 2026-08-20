// Package host validates Linux host admission conditions and safely prepares
// filesystem metadata for a future overlay mount. It does not mount, unshare,
// create namespaces, or execute a workload.
package host

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const Schema = "brick.host-isolation.host.v1"

var (
	ErrDenied      = errors.New("host admission denied")
	ErrUnavailable = errors.New("host admission unavailable")
)

// MountInfo is the reduced mount-table view needed for a safe propagation
// decision. The implementation fails closed when it cannot parse the table.
type MountInfo struct {
	MountPoint  string
	Propagation string
}

// Probe isolates host observation from policy evaluation. Production uses
// LinuxProbe; tests use deterministic probes without faking host side effects.
type Probe interface {
	GOOS() string
	ReadFile(string) ([]byte, error)
	Stat(string) (fs.FileInfo, error)
	Statfs(string) (syscall.Statfs_t, error)
	ReadMounts() ([]MountInfo, error)
	Now() (time.Time, error)
}

type LinuxProbe struct{}

func (LinuxProbe) GOOS() string                          { return runtime.GOOS }
func (LinuxProbe) ReadFile(path string) ([]byte, error)  { return os.ReadFile(path) }
func (LinuxProbe) Stat(path string) (fs.FileInfo, error) { return os.Lstat(path) }
func (LinuxProbe) Statfs(path string) (syscall.Statfs_t, error) {
	var value syscall.Statfs_t
	err := syscall.Statfs(path, &value)
	return value, err
}
func (LinuxProbe) Now() (time.Time, error)          { return time.Now().UTC(), nil }
func (LinuxProbe) ReadMounts() ([]MountInfo, error) { return readMountInfo("/proc/self/mountinfo") }

// PreflightConfig names the exact managed paths and services that must be safe
// before the broker authorizes a request. Empty configuration is rejected.
type PreflightConfig struct {
	ProtectedPaths       []string
	RequiredServiceFiles []string
	BaseRoot             string
	RequiredLSM          string
	Probe                Probe
	MinimumKernelMajor   int
	MinimumKernelMinor   int
}

// Preflight implements broker.HostPreflight. It caches no positive result so
// each authorization observes the current host state.
type Preflight struct{ config PreflightConfig }

func NewPreflight(config PreflightConfig) (*Preflight, error) {
	if config.Probe == nil || len(config.ProtectedPaths) == 0 || config.BaseRoot == "" || config.MinimumKernelMajor < 4 || config.MinimumKernelMinor < 0 {
		return nil, fmt.Errorf("%w: incomplete preflight configuration", ErrUnavailable)
	}
	if config.RequiredLSM == "" {
		config.RequiredLSM = "apparmor"
	}
	for _, value := range append(append([]string{}, config.ProtectedPaths...), append(config.RequiredServiceFiles, config.BaseRoot)...) {
		if !safeAbsolutePath(value) {
			return nil, fmt.Errorf("%w: unsafe configured path", ErrUnavailable)
		}
	}
	return &Preflight{config: config}, nil
}

func (p *Preflight) Check(ctx context.Context) error {
	if p == nil || p.config.Probe == nil {
		return fmt.Errorf("%w: nil preflight", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: request canceled", ErrUnavailable)
	}
	if p.config.Probe.GOOS() != "linux" {
		return deny("unsupported_platform")
	}
	if err := p.checkKernel(); err != nil {
		return err
	}
	if err := p.checkCgroupV2(); err != nil {
		return err
	}
	if err := p.checkUserNamespaces(); err != nil {
		return err
	}
	if err := p.checkSeccomp(); err != nil {
		return err
	}
	if err := p.checkLSM(); err != nil {
		return err
	}
	if _, err := p.config.Probe.Now(); err != nil {
		return fmt.Errorf("%w: clock unavailable", ErrUnavailable)
	}
	if err := p.checkMountPropagation(); err != nil {
		return err
	}
	for _, protected := range p.config.ProtectedPaths {
		if err := p.checkOwnerControlledPath(protected, false); err != nil {
			return err
		}
	}
	for _, required := range p.config.RequiredServiceFiles {
		if err := p.checkOwnerControlledPath(required, true); err != nil {
			return err
		}
	}
	if err := p.checkOwnerControlledPath(p.config.BaseRoot, false); err != nil {
		return err
	}
	return nil
}

func (p *Preflight) checkKernel() error {
	data, err := p.config.Probe.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return fmt.Errorf("%w: kernel version unavailable", ErrUnavailable)
	}
	var major, minor int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d.%d", &major, &minor); err != nil || major < p.config.MinimumKernelMajor || (major == p.config.MinimumKernelMajor && minor < p.config.MinimumKernelMinor) {
		return deny("kernel_version_inadequate")
	}
	return nil
}

func (p *Preflight) checkCgroupV2() error {
	data, err := p.config.Probe.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		return deny("cgroup_v2_unavailable")
	}
	return nil
}

func (p *Preflight) checkUserNamespaces() error {
	data, err := p.config.Probe.ReadFile("/proc/sys/user/max_user_namespaces")
	if err != nil {
		return fmt.Errorf("%w: user namespace setting unavailable", ErrUnavailable)
	}
	var count int64
	if _, err := fmt.Sscan(strings.TrimSpace(string(data)), &count); err != nil || count <= 0 {
		return deny("user_namespaces_disabled")
	}
	return nil
}

func (p *Preflight) checkSeccomp() error {
	data, err := p.config.Probe.ReadFile("/proc/sys/kernel/seccomp/actions_avail")
	if err != nil {
		return deny("seccomp_unavailable")
	}
	for _, action := range strings.Fields(string(data)) {
		if action == "filter" {
			return nil
		}
	}
	return deny("seccomp_unavailable")
}

func (p *Preflight) checkLSM() error {
	data, err := p.config.Probe.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return fmt.Errorf("%w: lsm state unavailable", ErrUnavailable)
	}
	present := false
	for _, lsm := range strings.Split(strings.TrimSpace(string(data)), ",") {
		if strings.TrimSpace(lsm) == p.config.RequiredLSM {
			present = true
			break
		}
	}
	if !present {
		return deny("required_lsm_unavailable")
	}
	var statePath, expected string
	switch p.config.RequiredLSM {
	case "apparmor":
		statePath, expected = "/sys/module/apparmor/parameters/enabled", "Y"
	case "selinux":
		statePath, expected = "/sys/fs/selinux/enforce", "1"
	default:
		return fmt.Errorf("%w: unsupported LSM posture source", ErrUnavailable)
	}
	state, err := p.config.Probe.ReadFile(statePath)
	if err != nil {
		return fmt.Errorf("%w: lsm enforcement state unavailable", ErrUnavailable)
	}
	if strings.TrimSpace(string(state)) != expected {
		return deny("required_lsm_not_enforcing")
	}
	return nil
}

func (p *Preflight) checkMountPropagation() error {
	mounts, err := p.config.Probe.ReadMounts()
	if err != nil {
		return fmt.Errorf("%w: mount information unavailable", ErrUnavailable)
	}
	for _, target := range append(append([]string{}, p.config.ProtectedPaths...), p.config.BaseRoot) {
		entry, ok := coveringMount(target, mounts)
		if !ok || entry.Propagation == "shared" || entry.Propagation == "slave" || entry.Propagation == "unbindable" {
			return deny("unsafe_mount_propagation")
		}
	}
	return nil
}

func (p *Preflight) checkOwnerControlledPath(path string, allowFile bool) error {
	info, err := p.config.Probe.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: required path unavailable", ErrUnavailable)
	}
	if info.Mode()&os.ModeSymlink != 0 || (!allowFile && !info.IsDir()) || (allowFile && !info.Mode().IsRegular()) || info.Mode().Perm()&0o022 != 0 || ownerUID(info) != 0 {
		return deny("unsafe_protected_path")
	}
	return nil
}

func deny(code string) error { return &DecisionError{Code: code} }

type DecisionError struct{ Code string }

func (e *DecisionError) Error() string        { return ErrDenied.Error() }
func (e *DecisionError) Is(target error) bool { return target == ErrDenied }

// BaseRootConfig names the root-controlled immutable tree and root-controlled
// ephemeral layer parent. Production uses ExpectedOwnerUID zero.
type BaseRootConfig struct {
	BaseRoot           string
	EphemeralRoot      string
	ExpectedOwnerUID   uint32
	ExpectedRootMode   os.FileMode
	AllowedFilesystems map[int64]struct{}
	Probe              Probe
}

type BaseRootAuthority struct {
	config BaseRootConfig
	mu     sync.Mutex
}

type Layer struct {
	CageID   string
	BaseRoot string
	UpperDir string
	WorkDir  string
}

func NewBaseRootAuthority(config BaseRootConfig) (*BaseRootAuthority, error) {
	if config.Probe == nil || !safeAbsolutePath(config.BaseRoot) || !safeAbsolutePath(config.EphemeralRoot) || config.BaseRoot == config.EphemeralRoot || config.ExpectedRootMode == 0 || len(config.AllowedFilesystems) == 0 {
		return nil, fmt.Errorf("%w: incomplete base-root configuration", ErrUnavailable)
	}
	return &BaseRootAuthority{config: config}, nil
}

// PrepareLayer validates the immutable base root then creates exactly one
// empty, owner-controlled upper/work directory pair. It creates no mount.
func (a *BaseRootAuthority) PrepareLayer(ctx context.Context, cageID string) (Layer, error) {
	if a == nil {
		return Layer{}, fmt.Errorf("%w: nil base-root authority", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return Layer{}, fmt.Errorf("%w: request canceled", ErrUnavailable)
	}
	if !validCageID(cageID) {
		return Layer{}, deny("invalid_cage_id")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validateBaseRoot(); err != nil {
		return Layer{}, err
	}
	if err := validateOwnerDirectory(a.config.EphemeralRoot, a.config.ExpectedOwnerUID, 0o700); err != nil {
		return Layer{}, err
	}
	parent := filepath.Join(a.config.EphemeralRoot, cageID)
	if err := os.Mkdir(parent, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return Layer{}, deny("ephemeral_layer_already_exists")
		}
		return Layer{}, fmt.Errorf("%w: create cage layer parent", ErrUnavailable)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(parent)
		}
	}()
	upper, work := filepath.Join(parent, "upper"), filepath.Join(parent, "work")
	if err := os.Mkdir(upper, 0o700); err != nil {
		return Layer{}, fmt.Errorf("%w: create upper layer", ErrUnavailable)
	}
	if err := os.Mkdir(work, 0o700); err != nil {
		return Layer{}, fmt.Errorf("%w: create work layer", ErrUnavailable)
	}
	if err := validateOwnerDirectory(parent, a.config.ExpectedOwnerUID, 0o700); err != nil {
		return Layer{}, err
	}
	if err := validateOwnerDirectory(upper, a.config.ExpectedOwnerUID, 0o700); err != nil {
		return Layer{}, err
	}
	if err := validateOwnerDirectory(work, a.config.ExpectedOwnerUID, 0o700); err != nil {
		return Layer{}, err
	}
	cleanup = false
	return Layer{CageID: cageID, BaseRoot: a.config.BaseRoot, UpperDir: upper, WorkDir: work}, nil
}

func (a *BaseRootAuthority) validateBaseRoot() error {
	if err := validateOwnerDirectory(a.config.BaseRoot, a.config.ExpectedOwnerUID, a.config.ExpectedRootMode); err != nil {
		return err
	}
	stat, err := a.config.Probe.Statfs(a.config.BaseRoot)
	if err != nil {
		return fmt.Errorf("%w: base-root filesystem unavailable", ErrUnavailable)
	}
	if _, ok := a.config.AllowedFilesystems[int64(stat.Type)]; !ok {
		return deny("unsafe_base_root_filesystem")
	}
	mounts, err := a.config.Probe.ReadMounts()
	if err != nil {
		return fmt.Errorf("%w: base-root mount information unavailable", ErrUnavailable)
	}
	entry, ok := coveringMount(a.config.BaseRoot, mounts)
	if !ok || entry.Propagation != "private" {
		return deny("unsafe_base_root_propagation")
	}
	return scanImmutableTree(a.config.BaseRoot, a.config.ExpectedOwnerUID)
}

func validateOwnerDirectory(path string, expectedUID uint32, expectedMode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: managed directory unavailable", ErrUnavailable)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != expectedMode || ownerUID(info) != expectedUID {
		return deny("unsafe_managed_directory")
	}
	return nil
}

func scanImmutableTree(root string, owner uint32) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("%w: read base-root entry", ErrUnavailable)
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("%w: inspect base-root entry", ErrUnavailable)
		}
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 || mode&os.ModeDevice != 0 || mode&os.ModeCharDevice != 0 || mode&0o6000 != 0 || mode.Perm()&0o022 != 0 || ownerUID(info) != owner {
			return deny("unsafe_base_root_entry")
		}
		return nil
	})
}

func ownerUID(info fs.FileInfo) uint32 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid
	}
	return ^uint32(0)
}

func validCageID(value string) bool {
	if !strings.HasPrefix(value, "cage-") || len(value) < 8 || len(value) > 68 {
		return false
	}
	for _, char := range value {
		if !(char == '-' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func safeAbsolutePath(value string) bool {
	return strings.HasPrefix(value, "/") && filepath.Clean(value) == value && value != "/" && !strings.Contains(value, "//")
}

func coveringMount(target string, mounts []MountInfo) (MountInfo, bool) {
	var result MountInfo
	matched := false
	for _, mount := range mounts {
		covers := mount.MountPoint == "/" || target == mount.MountPoint || strings.HasPrefix(target, mount.MountPoint+"/")
		if covers {
			if !matched || len(mount.MountPoint) > len(result.MountPoint) {
				result, matched = mount, true
			}
		}
	}
	return result, matched
}

func readMountInfo(path string) ([]MountInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result []MountInfo
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			return nil, errors.New("malformed mountinfo")
		}
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 {
			return nil, errors.New("malformed mountinfo separator")
		}
		propagation := "private"
		for _, option := range fields[6:separator] {
			if strings.HasPrefix(option, "shared:") {
				propagation = "shared"
			}
			if strings.HasPrefix(option, "master:") {
				propagation = "slave"
			}
			if option == "unbindable" {
				propagation = "unbindable"
			}
		}
		result = append(result, MountInfo{MountPoint: strings.ReplaceAll(fields[4], "\\040", " "), Propagation: propagation})
	}
	return result, nil
}
