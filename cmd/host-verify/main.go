package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/brick/host-isolation/host"
)

type probe struct {
	files map[string]string
	stats map[string]fs.FileInfo
}

func (p probe) GOOS() string { return "linux" }
func (p probe) ReadFile(path string) ([]byte, error) {
	value, ok := p.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(value), nil
}
func (p probe) Stat(path string) (fs.FileInfo, error) {
	value, ok := p.stats[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return value, nil
}
func (p probe) Statfs(string) (syscall.Statfs_t, error) { return syscall.Statfs_t{Type: 0xEF53}, nil }
func (p probe) ReadMounts() ([]host.MountInfo, error) {
	return []host.MountInfo{{MountPoint: "/", Propagation: "private"}}, nil
}
func (p probe) Now() (time.Time, error) { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC), nil }

type info struct {
	mode fs.FileMode
	uid  uint32
}

func (i info) Name() string       { return "managed" }
func (i info) Size() int64        { return 0 }
func (i info) Mode() fs.FileMode  { return i.mode }
func (i info) ModTime() time.Time { return time.Time{} }
func (i info) IsDir() bool        { return i.mode.IsDir() }
func (i info) Sys() any           { return &syscall.Stat_t{Uid: i.uid} }

func main() {
	if err := verify(); err != nil {
		fmt.Fprintf(os.Stderr, "host-isolation host verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("host-isolation host verification passed")
}

func verify() error {
	data, err := os.ReadFile("contracts/brick-host-isolation-host.v1.json")
	if err != nil {
		return err
	}
	var contract struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &contract); err != nil || contract.Schema != host.Schema {
		return fmt.Errorf("invalid host contract")
	}
	uid := uint32(os.Getuid())
	directory, err := os.MkdirTemp("/tmp", "brick-host-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	base, layers := filepath.Join(directory, "base"), filepath.Join(directory, "layers")
	if err := os.Mkdir(base, 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(layers, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(base, "runtime-manifest"), []byte("verified"), 0o644); err != nil {
		return err
	}
	verificationProbe := probe{files: map[string]string{
		"/proc/sys/kernel/osrelease": "6.8.0-verify\n", "/sys/fs/cgroup/cgroup.controllers": "cpu memory pids\n", "/proc/sys/user/max_user_namespaces": "1024\n", "/proc/sys/kernel/seccomp/actions_avail": "kill_process allow filter\n", "/sys/kernel/security/lsm": "capability,apparmor\n", "/sys/module/apparmor/parameters/enabled": "Y\n",
	}, stats: map[string]fs.FileInfo{"/opt/brick": info{mode: fs.ModeDir | 0o755, uid: 0}, "/var/lib/brick": info{mode: fs.ModeDir | 0o750, uid: 0}, "/run/brick/ready": info{mode: 0o640, uid: 0}, base: info{mode: fs.ModeDir | 0o755, uid: 0}}}
	preflight, err := host.NewPreflight(host.PreflightConfig{ProtectedPaths: []string{"/opt/brick", "/var/lib/brick"}, RequiredServiceFiles: []string{"/run/brick/ready"}, BaseRoot: base, RequiredLSM: "apparmor", Probe: verificationProbe, MinimumKernelMajor: 5, MinimumKernelMinor: 10})
	if err != nil {
		return err
	}
	if err := preflight.Check(context.Background()); err != nil {
		return err
	}
	authority, err := host.NewBaseRootAuthority(host.BaseRootConfig{BaseRoot: base, EphemeralRoot: layers, ExpectedOwnerUID: uid, ExpectedRootMode: 0o755, AllowedFilesystems: map[int64]struct{}{0xEF53: {}}, Probe: verificationProbe})
	if err != nil {
		return err
	}
	layer, err := authority.PrepareLayer(context.Background(), "cage-verify-a")
	if err != nil {
		return err
	}
	for _, path := range []string{layer.UpperDir, layer.WorkDir} {
		entry, err := os.Lstat(path)
		if err != nil || !entry.IsDir() || entry.Mode().Perm() != 0o700 {
			return fmt.Errorf("unsafe layer preparation")
		}
	}
	return nil
}
