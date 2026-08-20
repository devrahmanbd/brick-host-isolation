package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/brick/host-isolation/isolation"
	"github.com/brick/host-isolation/lifecycle"
	"github.com/brick/host-isolation/resource"
)

type preflight struct{}

func (preflight) Check(context.Context) error { return nil }

type audit struct{}

func (audit) RecordEvent(string, string, string, string, map[string]any) error { return nil }

type cgroupFS struct{ writes int }

func (*cgroupFS) Mkdir(string, uint32) error       { return nil }
func (f *cgroupFS) WriteFile(string, string) error { f.writes++; return nil }
func (*cgroupFS) Remove(string) error              { return nil }

func main() {
	if err := verify(); err != nil {
		fmt.Fprintf(os.Stderr, "host-isolation resource verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("host-isolation resource verification passed")
}

func verify() error {
	data, err := os.ReadFile("contracts/brick-host-isolation-resource.v1.json")
	if err != nil {
		return err
	}
	var contract struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &contract); err != nil || contract.Schema != resource.Schema {
		return fmt.Errorf("invalid resource contract")
	}
	isolationAuthority, err := isolation.NewAuthority(preflight{}, audit{})
	if err != nil {
		return err
	}
	isolationRequest := isolation.Request{Schema: isolation.Schema, CageID: "cage-verify-a", Profile: lifecycle.ProfileSharedTenant, BaseRootDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SeccompDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Namespaces: []string{"user", "pid", "mount", "ipc", "uts", "network"}, UIDMappings: []isolation.UIDMap{{ContainerID: 0, HostID: 100001, Size: 1}}, GIDMappings: []isolation.UIDMap{{ContainerID: 0, HostID: 100001, Size: 1}}, Mounts: []isolation.MountSpec{{SourceKind: "baseRoot", Destination: "/", ReadOnly: true, Flags: []string{"nodev", "nosuid", "noexec", "readonly"}, Options: []string{"privatePropagation"}}, {SourceKind: "proc", Destination: "/proc", ReadOnly: true, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"hidepid=2", "subset=pid"}}, {SourceKind: "minimalDev", Destination: "/dev", ReadOnly: false, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"mode=0755", "size=16m"}}, {SourceKind: "tmpfs", Destination: "/tmp", ReadOnly: false, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"mode=1777", "size=64m"}}}, Devices: []string{"null", "zero", "random", "urandom"}, NoNewPrivileges: true, ClearEnvironment: true, CloseDescriptorsAt: 3, ParentDeathSignal: "SIGKILL", InitMode: "supervisedReaper", WorkingDirectory: "/", Capabilities: []string{}}
	isolationPlan, err := isolationAuthority.Prepare(context.Background(), "spiffe://brick/verify", isolationRequest)
	if err != nil {
		return err
	}
	maximum := resource.Limits{CPUQuotaMicros: 100000, CPUPeriodMicros: 100000, MemoryMaxBytes: 2 << 30, MemoryHighBytes: 1536 << 20, MemorySwapMaxBytes: 2 << 30, PidsMax: 128, IO: []resource.IOThrottle{{Device: "8:0", ReadBPS: 10 << 20, WriteBPS: 10 << 20, ReadIOPS: 1000, WriteIOPS: 1000}}, FileDescriptorMax: 1024, WallClockSeconds: 3600}
	authority, err := resource.NewAuthority("/sys/fs/cgroup/brick-isolation", maximum, audit{})
	if err != nil {
		return err
	}
	request := resource.Request{Schema: resource.Schema, CageID: isolationPlan.CageID, Profile: isolationPlan.Profile, IsolationPlanDigest: isolationPlan.PlanDigest, Limits: resource.Limits{CPUQuotaMicros: 50000, CPUPeriodMicros: 100000, MemoryMaxBytes: 1 << 30, MemoryHighBytes: 900 << 20, MemorySwapMaxBytes: 0, PidsMax: 64, IO: []resource.IOThrottle{{Device: "8:0", ReadBPS: 5 << 20, WriteBPS: 5 << 20, ReadIOPS: 500, WriteIOPS: 500}}, FileDescriptorMax: 512, WallClockSeconds: 600}, Network: resource.NetworkPolicy{Mode: "denyAll"}}
	plan, err := authority.Prepare(context.Background(), "spiffe://brick/verify", isolationPlan, request)
	if err != nil {
		return err
	}
	if err := authority.VerifyPlan(plan); err != nil {
		return err
	}
	fs := &cgroupFS{}
	if err := authority.ApplyCgroup(context.Background(), plan, fs); err != nil {
		return err
	}
	if fs.writes != 6 {
		return fmt.Errorf("incomplete cgroup write sequence")
	}
	return nil
}
