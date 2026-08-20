package isolation

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/brick/host-isolation/lifecycle"
)

type preflight struct{ err error }

func (p preflight) Check(context.Context) error { return p.err }

type audit struct {
	mu          sync.Mutex
	events      int
	fail        bool
	lastOutcome string
}

func (a *audit) RecordEvent(_ string, _ string, outcome string, _ string, _ map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events++
	a.lastOutcome = outcome
	if a.fail {
		return errors.New("audit failure")
	}
	return nil
}

func validRequest() Request {
	return Request{Schema: Schema, CageID: "cage-tenant-a", Profile: lifecycle.ProfileSharedTenant, BaseRootDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SeccompDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Namespaces: []string{"user", "pid", "mount", "ipc", "uts", "network"}, UIDMappings: []UIDMap{{ContainerID: 0, HostID: 100001, Size: 1}}, GIDMappings: []UIDMap{{ContainerID: 0, HostID: 100001, Size: 1}}, Mounts: []MountSpec{{SourceKind: "tmpfs", Destination: "/tmp", ReadOnly: false, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"size=64m", "mode=1777"}}, {SourceKind: "minimalDev", Destination: "/dev", ReadOnly: false, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"size=16m", "mode=0755"}}, {SourceKind: "proc", Destination: "/proc", ReadOnly: true, Flags: []string{"nodev", "nosuid", "noexec"}, Options: []string{"subset=pid", "hidepid=2"}}, {SourceKind: "baseRoot", Destination: "/", ReadOnly: true, Flags: []string{"nodev", "nosuid", "noexec", "readonly"}, Options: []string{"privatePropagation"}}}, Devices: []string{"null", "zero", "random", "urandom"}, NoNewPrivileges: true, ClearEnvironment: true, CloseDescriptorsAt: 3, ParentDeathSignal: "SIGKILL", InitMode: "supervisedReaper", WorkingDirectory: "/", Capabilities: []string{}}
}

func newAuthority(t *testing.T, preflightError error, auditFailure bool) (*Authority, *audit) {
	t.Helper()
	sink := &audit{fail: auditFailure}
	authority, err := NewAuthority(preflight{err: preflightError}, sink)
	if err != nil {
		t.Fatal(err)
	}
	return authority, sink
}

func TestPrepareProducesDeterministicVerifiablePlan(t *testing.T) {
	authority, sink := newAuthority(t, nil, false)
	first, err := authority.Prepare(context.Background(), "spiffe://brick/shared-adapter", validRequest())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := VerifyPlan(first); err != nil {
		t.Fatalf("VerifyPlan() error = %v", err)
	}
	request := validRequest()
	request.Namespaces = []string{"network", "uts", "ipc", "mount", "pid", "user"}
	request.Devices = []string{"urandom", "random", "zero", "null"}
	second, err := authority.Prepare(context.Background(), "spiffe://brick/shared-adapter", request)
	if err != nil {
		t.Fatalf("Prepare() reordered error = %v", err)
	}
	if first.PlanDigest != second.PlanDigest || sink.events != 2 || first.CloseDescriptorsAt != 3 || len(first.CapabilityBoundingSet) != 0 {
		t.Fatalf("unexpected plan: %+v, second=%+v, events=%d", first, second, sink.events)
	}
}

func TestPrepareRejectsMalformedIsolationBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{"missing network namespace", func(r *Request) { r.Namespaces = r.Namespaces[:5] }},
		{"host root uid mapping", func(r *Request) { r.UIDMappings[0].HostID = 0 }},
		{"inherited capability", func(r *Request) { r.Capabilities = []string{"CAP_NET_ADMIN"} }},
		{"no new privileges disabled", func(r *Request) { r.NoNewPrivileges = false }},
		{"descriptors not closed", func(r *Request) { r.CloseDescriptorsAt = 4 }},
		{"unsafe working directory", func(r *Request) { r.WorkingDirectory = "/tmp" }},
		{"unsafe device set", func(r *Request) { r.Devices[0] = "kmsg" }},
		{"base root writable", func(r *Request) { r.Mounts[3].ReadOnly = false }},
		{"unsafe proc options", func(r *Request) { r.Mounts[2].Options = []string{"hidepid=0", "subset=pid"} }},
		{"unsafe tmp options", func(r *Request) { r.Mounts[0].Options = []string{"mode=1777", "size=8g"} }},
		{"protected destination", func(r *Request) { r.Mounts[0].Destination = "/run/brick/escape" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority, sink := newAuthority(t, nil, false)
			request := validRequest()
			test.mutate(&request)
			if _, err := authority.Prepare(context.Background(), "spiffe://brick/shared-adapter", request); !errors.Is(err, ErrDenied) {
				t.Fatalf("Prepare() error = %v", err)
			}
			if sink.events != 1 || sink.lastOutcome != "denied" {
				t.Fatalf("denial was not audited: %+v", sink)
			}
		})
	}
}

func TestPrepareFailsClosedForPreflightAuditAndCancellation(t *testing.T) {
	t.Run("preflight failure", func(t *testing.T) {
		authority, sink := newAuthority(t, errors.New("preflight unavailable"), false)
		if _, err := authority.Prepare(context.Background(), "actor", validRequest()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Prepare() error = %v", err)
		}
		if sink.lastOutcome != "denied" {
			t.Fatal("preflight denial was not audited")
		}
	})
	t.Run("audit failure", func(t *testing.T) {
		authority, _ := newAuthority(t, nil, true)
		if _, err := authority.Prepare(context.Background(), "actor", validRequest()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Prepare() error = %v", err)
		}
	})
	t.Run("cancelled request", func(t *testing.T) {
		authority, sink := newAuthority(t, nil, false)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := authority.Prepare(ctx, "actor", validRequest()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Prepare() error = %v", err)
		}
		if sink.lastOutcome != "denied" {
			t.Fatal("cancellation was not audited")
		}
	})
}

func TestVerifyPlanRejectsTamperedPlan(t *testing.T) {
	authority, _ := newAuthority(t, nil, false)
	plan, err := authority.Prepare(context.Background(), "actor", validRequest())
	if err != nil {
		t.Fatal(err)
	}
	plan.Mounts[0].Options = []string{"mode=1777", "size=8g"}
	if err := VerifyPlan(plan); !errors.Is(err, ErrDenied) {
		t.Fatalf("VerifyPlan() error = %v", err)
	}
}
