package host

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type fakeProbe struct {
	goos       string
	files      map[string]string
	fileErrors map[string]error
	stats      map[string]fs.FileInfo
	statErrors map[string]error
	statfs     syscall.Statfs_t
	statfsErr  error
	mounts     []MountInfo
	mountErr   error
	nowErr     error
}

func (p *fakeProbe) GOOS() string { return p.goos }
func (p *fakeProbe) ReadFile(path string) ([]byte, error) {
	if err := p.fileErrors[path]; err != nil {
		return nil, err
	}
	value, ok := p.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(value), nil
}
func (p *fakeProbe) Stat(path string) (fs.FileInfo, error) {
	if err := p.statErrors[path]; err != nil {
		return nil, err
	}
	value, ok := p.stats[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return value, nil
}
func (p *fakeProbe) Statfs(string) (syscall.Statfs_t, error) { return p.statfs, p.statfsErr }
func (p *fakeProbe) ReadMounts() ([]MountInfo, error)        { return p.mounts, p.mountErr }
func (p *fakeProbe) Now() (time.Time, error) {
	return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC), p.nowErr
}

type fakeInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (i fakeInfo) Name() string       { return "entry" }
func (i fakeInfo) Size() int64        { return 0 }
func (i fakeInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid} }

func validPreflightFixture() (*Preflight, *fakeProbe, error) {
	probe := &fakeProbe{
		goos: "linux",
		files: map[string]string{
			"/proc/sys/kernel/osrelease":              "6.8.0-test\n",
			"/sys/fs/cgroup/cgroup.controllers":       "cpu memory pids\n",
			"/proc/sys/user/max_user_namespaces":      "1024\n",
			"/proc/sys/kernel/seccomp/actions_avail":  "kill_process trap errno user_notif trace log allow filter\n",
			"/sys/kernel/security/lsm":                "capability,apparmor\n",
			"/sys/module/apparmor/parameters/enabled": "Y\n",
		},
		fileErrors: map[string]error{}, statErrors: map[string]error{},
		stats: map[string]fs.FileInfo{
			"/opt/brick":       fakeInfo{mode: fs.ModeDir | 0o755, uid: 0},
			"/var/lib/brick":   fakeInfo{mode: fs.ModeDir | 0o750, uid: 0},
			"/srv/brick-base":  fakeInfo{mode: fs.ModeDir | 0o755, uid: 0},
			"/run/brick/ready": fakeInfo{mode: 0o640, uid: 0},
		},
		mounts: []MountInfo{{MountPoint: "/", Propagation: "private"}},
	}
	preflight, err := NewPreflight(PreflightConfig{ProtectedPaths: []string{"/opt/brick", "/var/lib/brick"}, RequiredServiceFiles: []string{"/run/brick/ready"}, BaseRoot: "/srv/brick-base", RequiredLSM: "apparmor", Probe: probe, MinimumKernelMajor: 5, MinimumKernelMinor: 10})
	return preflight, probe, err
}

func TestPreflightAcceptsFullyCompliantHost(t *testing.T) {
	preflight, _, err := validPreflightFixture()
	if err != nil {
		t.Fatal(err)
	}
	if err := preflight.Check(context.Background()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestPreflightFailsClosedForCapabilityAndPathViolations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeProbe)
		want   error
	}{
		{"unsupported platform", func(p *fakeProbe) { p.goos = "darwin" }, ErrDenied},
		{"kernel unreadable", func(p *fakeProbe) { p.fileErrors["/proc/sys/kernel/osrelease"] = errors.New("denied") }, ErrUnavailable},
		{"cgroup v2 missing", func(p *fakeProbe) { p.files["/sys/fs/cgroup/cgroup.controllers"] = "" }, ErrDenied},
		{"user namespaces disabled", func(p *fakeProbe) { p.files["/proc/sys/user/max_user_namespaces"] = "0" }, ErrDenied},
		{"seccomp missing", func(p *fakeProbe) { p.files["/proc/sys/kernel/seccomp/actions_avail"] = "allow" }, ErrDenied},
		{"required lsm absent", func(p *fakeProbe) { p.files["/sys/kernel/security/lsm"] = "capability,yama" }, ErrDenied},
		{"required lsm not enforcing", func(p *fakeProbe) { p.files["/sys/module/apparmor/parameters/enabled"] = "N" }, ErrDenied},
		{"unsafe mount propagation", func(p *fakeProbe) { p.mounts = []MountInfo{{MountPoint: "/", Propagation: "shared"}} }, ErrDenied},
		{"world writable protected path", func(p *fakeProbe) { p.stats["/opt/brick"] = fakeInfo{mode: fs.ModeDir | 0o777, uid: 0} }, ErrDenied},
		{"untrusted protected owner", func(p *fakeProbe) { p.stats["/var/lib/brick"] = fakeInfo{mode: fs.ModeDir | 0o750, uid: 1000} }, ErrDenied},
		{"service state unavailable", func(p *fakeProbe) { p.statErrors["/run/brick/ready"] = os.ErrNotExist }, ErrUnavailable},
		{"clock unavailable", func(p *fakeProbe) { p.nowErr = errors.New("clock failure") }, ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			preflight, probe, err := validPreflightFixture()
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(probe)
			if err := preflight.Check(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("Check() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPreflightHonorsCancellationAndRejectsIncompleteConfiguration(t *testing.T) {
	if _, err := NewPreflight(PreflightConfig{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewPreflight() error = %v", err)
	}
	preflight, _, err := validPreflightFixture()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := preflight.Check(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestBaseRootPreparationCreatesOnlySafeEphemeralLayer(t *testing.T) {
	dir := t.TempDir()
	base, ephemeral := filepath.Join(dir, "base"), filepath.Join(dir, "layers")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ephemeral, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "runtime.txt"), []byte("immutable"), 0o644); err != nil {
		t.Fatal(err)
	}
	probe := &fakeProbe{goos: "linux", files: map[string]string{}, fileErrors: map[string]error{}, stats: map[string]fs.FileInfo{}, statErrors: map[string]error{}, statfs: syscall.Statfs_t{Type: 0xEF53}, mounts: []MountInfo{{MountPoint: "/", Propagation: "private"}}}
	authority, err := NewBaseRootAuthority(BaseRootConfig{BaseRoot: base, EphemeralRoot: ephemeral, ExpectedOwnerUID: uint32(os.Getuid()), ExpectedRootMode: 0o755, AllowedFilesystems: map[int64]struct{}{0xEF53: {}}, Probe: probe})
	if err != nil {
		t.Fatal(err)
	}
	layer, err := authority.PrepareLayer(context.Background(), "cage-tenant-a")
	if err != nil {
		t.Fatalf("PrepareLayer() error = %v", err)
	}
	for _, path := range []string{layer.UpperDir, layer.WorkDir} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("unsafe layer path %s: %v %+v", path, err, info)
		}
	}
	if _, err := authority.PrepareLayer(context.Background(), "cage-tenant-a"); !errors.Is(err, ErrDenied) {
		t.Fatalf("duplicate PrepareLayer() error = %v", err)
	}
}

func TestBaseRootPreparationRejectsUnsafeTreeAndFilesystem(t *testing.T) {
	dir := t.TempDir()
	base, ephemeral := filepath.Join(dir, "base"), filepath.Join(dir, "layers")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ephemeral, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "unsafe"), []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(base, "unsafe"), 0o666); err != nil {
		t.Fatal(err)
	}
	probe := &fakeProbe{goos: "linux", files: map[string]string{}, fileErrors: map[string]error{}, stats: map[string]fs.FileInfo{}, statErrors: map[string]error{}, statfs: syscall.Statfs_t{Type: 0xEF53}, mounts: []MountInfo{{MountPoint: "/", Propagation: "private"}}}
	authority, err := NewBaseRootAuthority(BaseRootConfig{BaseRoot: base, EphemeralRoot: ephemeral, ExpectedOwnerUID: uint32(os.Getuid()), ExpectedRootMode: 0o755, AllowedFilesystems: map[int64]struct{}{0xEF53: {}}, Probe: probe})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.PrepareLayer(context.Background(), "cage-unsafe-a"); !errors.Is(err, ErrDenied) {
		t.Fatalf("unsafe tree error = %v", err)
	}
	if err := os.Chmod(filepath.Join(base, "unsafe"), 0o644); err != nil {
		t.Fatal(err)
	}
	probe.statfs.Type = 0x6969
	if _, err := authority.PrepareLayer(context.Background(), "cage-filesystem-a"); !errors.Is(err, ErrDenied) {
		t.Fatalf("unsafe filesystem error = %v", err)
	}
}
