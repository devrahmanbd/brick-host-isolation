package resource

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/brick/host-isolation/isolation"
	"github.com/brick/host-isolation/lifecycle"
)

type audit struct {
	mu      sync.Mutex
	events  int
	outcome string
	fail    bool
}

func (a *audit) RecordEvent(_ string, _ string, outcome string, _ string, _ map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events++
	a.outcome = outcome
	if a.fail {
		return errors.New("audit unavailable")
	}
	return nil
}

type cleanPreflight struct{}

func (cleanPreflight) Check(context.Context) error { return nil }

type memoryCgroupFS struct {
	mkdirs    []string
	writes    []string
	removed   []string
	failAfter int
	calls     int
}

func (f *memoryCgroupFS) Mkdir(path string, _ uint32) error {
	f.mkdirs = append(f.mkdirs, path)
	return nil
}
func (f *memoryCgroupFS) WriteFile(path, _ string) error {
	f.calls++
	f.writes = append(f.writes, path)
	if f.failAfter > 0 && f.calls >= f.failAfter {
		return errors.New("write failure")
	}
	return nil
}
func (f *memoryCgroupFS) Remove(path string) error { f.removed = append(f.removed, path); return nil }

func maximum() Limits {
	return Limits{CPUQuotaMicros: 100000, CPUPeriodMicros: 100000, MemoryMaxBytes: 2 << 30, MemoryHighBytes: 1536 << 20, MemorySwapMaxBytes: 2 << 30, PidsMax: 128, IO: []IOThrottle{{Device: "8:0", ReadBPS: 10 << 20, WriteBPS: 10 << 20, ReadIOPS: 1000, WriteIOPS: 1000}}, FileDescriptorMax: 1024, WallClockSeconds: 3600}
}
func request() Request {
	return Request{Schema: Schema, CageID: "cage-tenant-a", Profile: lifecycle.ProfileSharedTenant, Limits: Limits{CPUQuotaMicros: 50000, CPUPeriodMicros: 100000, MemoryMaxBytes: 1 << 30, MemoryHighBytes: 900 << 20, MemorySwapMaxBytes: 0, PidsMax: 64, IO: []IOThrottle{{Device: "8:0", ReadBPS: 5 << 20, WriteBPS: 5 << 20, ReadIOPS: 500, WriteIOPS: 500}}, FileDescriptorMax: 512, WallClockSeconds: 600}, Network: NetworkPolicy{Mode: "denyAll"}}
}

func isolationPlan(t *testing.T) isolation.Plan {
	t.Helper()
	sink := &audit{}
	authority, err := isolation.NewAuthority(cleanPreflight{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	request := isolation.Request{Schema: isolation.Schema, CageID: "cage-tenant-a", Profile: lifecycle.ProfileSharedTenant, BaseRootDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SeccompDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Namespaces: []string{"user", "pid", "mount", "ipc", "uts", "network"}, UIDMappings: []isolation.UIDMap{{ContainerID: 0, HostID: 100001, Size: 1}}, GIDMappings: []isolation.UIDMap{{ContainerID: 0, HostID: 100001, Size: 1}}, Mounts: []isolation.MountSpec{{SourceKind: "baseRoot", Destination: "/", ReadOnly: true, Flags: []string{"nodev", "nosuid", "noexec", "readonly"}, Options: []string{"privatePropagation"}}, {SourceKind: "proc", Destination: "/proc", ReadOnly: true, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"hidepid=2", "subset=pid"}}, {SourceKind: "minimalDev", Destination: "/dev", ReadOnly: false, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"mode=0755", "size=16m"}}, {SourceKind: "tmpfs", Destination: "/tmp", ReadOnly: false, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"mode=1777", "size=64m"}}}, Devices: []string{"null", "zero", "random", "urandom"}, NoNewPrivileges: true, ClearEnvironment: true, CloseDescriptorsAt: 3, ParentDeathSignal: "SIGKILL", InitMode: "supervisedReaper", WorkingDirectory: "/", Capabilities: []string{}}
	plan, err := authority.Prepare(context.Background(), "spiffe://brick/test", request)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func newAuthority(t *testing.T, failAudit bool) (*Authority, *audit) {
	t.Helper()
	sink := &audit{fail: failAudit}
	authority, err := NewAuthority("/sys/fs/cgroup/brick-isolation", maximum(), sink)
	if err != nil {
		t.Fatal(err)
	}
	return authority, sink
}

func prepared(t *testing.T) (*Authority, *audit, isolation.Plan, Request, Plan) {
	t.Helper()
	authority, sink := newAuthority(t, false)
	isolated := isolationPlan(t)
	request := request()
	request.IsolationPlanDigest = isolated.PlanDigest
	plan, err := authority.Prepare(context.Background(), "spiffe://brick/shared-adapter", isolated, request)
	if err != nil {
		t.Fatal(err)
	}
	return authority, sink, isolated, request, plan
}

func TestPrepareAndApplyCgroupPlan(t *testing.T) {
	authority, sink, _, _, plan := prepared(t)
	if err := authority.VerifyPlan(plan); err != nil {
		t.Fatalf("VerifyPlan() error = %v", err)
	}
	fs := &memoryCgroupFS{}
	if err := authority.ApplyCgroup(context.Background(), plan, fs); err != nil {
		t.Fatalf("ApplyCgroup() error = %v", err)
	}
	if len(fs.mkdirs) != 1 || len(fs.writes) != 6 || len(fs.removed) != 0 || sink.events != 2 {
		t.Fatalf("unexpected application result: %+v audit=%+v", fs, sink)
	}
}

func TestPrepareRejectsInvalidResourceAndNetworkBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request, *isolation.Plan)
	}{
		{"mismatched isolation digest", func(r *Request, _ *isolation.Plan) {
			r.IsolationPlanDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		}},
		{"cpu above maximum", func(r *Request, _ *isolation.Plan) { r.Limits.CPUQuotaMicros = 100001 }},
		{"memory high above max", func(r *Request, _ *isolation.Plan) { r.Limits.MemoryHighBytes = r.Limits.MemoryMaxBytes + 1 }},
		{"no process limit", func(r *Request, _ *isolation.Plan) { r.Limits.PidsMax = 0 }},
		{"duplicate io device", func(r *Request, _ *isolation.Plan) { r.Limits.IO = append(r.Limits.IO, r.Limits.IO[0]) }},
		{"unbounded file descriptors", func(r *Request, _ *isolation.Plan) { r.Limits.FileDescriptorMax = 0 }},
		{"deny all leaks endpoint", func(r *Request, _ *isolation.Plan) {
			r.Network.AllowedEndpoints = []Endpoint{{ServerName: "api.example.test", Protocol: "https", Port: 443}}
		}},
		{"proxy uses http", func(r *Request, _ *isolation.Plan) {
			r.Network = NetworkPolicy{Mode: "proxyOnly", ProxySPIFFEID: "spiffe://brick/egress-proxy", AllowedEndpoints: []Endpoint{{ServerName: "api.example.test", Protocol: "http", Port: 80}}}
		}},
		{"tampered isolation plan", func(_ *Request, plan *isolation.Plan) { plan.NoNewPrivileges = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority, sink := newAuthority(t, false)
			isolated := isolationPlan(t)
			candidate := request()
			candidate.IsolationPlanDigest = isolated.PlanDigest
			test.mutate(&candidate, &isolated)
			if _, err := authority.Prepare(context.Background(), "actor", isolated, candidate); !errors.Is(err, ErrDenied) {
				t.Fatalf("Prepare() error = %v", err)
			}
			if sink.events != 1 || sink.outcome != "denied" {
				t.Fatalf("denial was not audited: %+v", sink)
			}
		})
	}
}

func TestApplyCgroupFailsClosedAndCleansIncompleteState(t *testing.T) {
	authority, _, _, _, plan := prepared(t)
	fs := &memoryCgroupFS{failAfter: 2}
	if err := authority.ApplyCgroup(context.Background(), plan, fs); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ApplyCgroup() error = %v", err)
	}
	if len(fs.removed) != 1 || fs.removed[0] != plan.Cgroup.Path {
		t.Fatalf("incomplete cgroup was not removed: %+v", fs)
	}
	plan.Network.Mode = "proxyOnly"
	if err := authority.VerifyPlan(plan); !errors.Is(err, ErrDenied) {
		t.Fatalf("VerifyPlan(tampered) error = %v", err)
	}
}

func TestAuthorityFailsClosedForAuditAndCancellation(t *testing.T) {
	isolated := isolationPlan(t)
	candidate := request()
	candidate.IsolationPlanDigest = isolated.PlanDigest
	authority, _ := newAuthority(t, true)
	if _, err := authority.Prepare(context.Background(), "actor", isolated, candidate); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Prepare(audit failure) error = %v", err)
	}
	authority, _ = newAuthority(t, false)
	context, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := authority.Prepare(context, "actor", isolated, candidate); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Prepare(cancelled) error = %v", err)
	}
}
