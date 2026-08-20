package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/brick/host-isolation/isolation"
	"github.com/brick/host-isolation/lifecycle"
)

type preflight struct{}

func (preflight) Check(context.Context) error { return nil }

type audit struct{}

func (audit) RecordEvent(string, string, string, string, map[string]any) error { return nil }

func main() {
	if err := verify(); err != nil {
		fmt.Fprintf(os.Stderr, "host-isolation plan verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("host-isolation plan verification passed")
}

func verify() error {
	data, err := os.ReadFile("contracts/brick-host-isolation-isolation.v1.json")
	if err != nil {
		return err
	}
	var contract struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &contract); err != nil || contract.Schema != isolation.Schema {
		return fmt.Errorf("invalid isolation contract")
	}
	authority, err := isolation.NewAuthority(preflight{}, audit{})
	if err != nil {
		return err
	}
	request := isolation.Request{Schema: isolation.Schema, CageID: "cage-verify-a", Profile: lifecycle.ProfileSharedTenant, BaseRootDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SeccompDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Namespaces: []string{"user", "pid", "mount", "ipc", "uts", "network"}, UIDMappings: []isolation.UIDMap{{ContainerID: 0, HostID: 100001, Size: 1}}, GIDMappings: []isolation.UIDMap{{ContainerID: 0, HostID: 100001, Size: 1}}, Mounts: []isolation.MountSpec{{SourceKind: "baseRoot", Destination: "/", ReadOnly: true, Flags: []string{"nodev", "nosuid", "noexec", "readonly"}, Options: []string{"privatePropagation"}}, {SourceKind: "proc", Destination: "/proc", ReadOnly: true, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"hidepid=2", "subset=pid"}}, {SourceKind: "minimalDev", Destination: "/dev", ReadOnly: false, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"mode=0755", "size=16m"}}, {SourceKind: "tmpfs", Destination: "/tmp", ReadOnly: false, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"mode=1777", "size=64m"}}}, Devices: []string{"null", "zero", "random", "urandom"}, NoNewPrivileges: true, ClearEnvironment: true, CloseDescriptorsAt: 3, ParentDeathSignal: "SIGKILL", InitMode: "supervisedReaper", WorkingDirectory: "/", Capabilities: []string{}}
	plan, err := authority.Prepare(context.Background(), "spiffe://brick/verify", request)
	if err != nil {
		return err
	}
	return isolation.VerifyPlan(plan)
}
