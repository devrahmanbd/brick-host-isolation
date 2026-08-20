package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type memoryAudit struct {
	mu     sync.Mutex
	fail   bool
	events int
}

func (a *memoryAudit) RecordEvent(_ string, _ string, _ string, _ string, _ map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events++
	if a.fail {
		return errors.New("audit unavailable")
	}
	return nil
}

type memoryReplay struct {
	mu   sync.Mutex
	fail bool
	seen map[string]time.Time
}

func (r *memoryReplay) Claim(id string, expiry time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return false, errors.New("replay unavailable")
	}
	if _, exists := r.seen[id]; exists {
		return false, nil
	}
	r.seen[id] = expiry
	return true, nil
}

type fixture struct {
	now       time.Time
	callerKey ed25519.PrivateKey
	engineKey ed25519.PrivateKey
	audit     *memoryAudit
	replay    *memoryReplay
	authority *Authority
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	callerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	engineKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	audit := &memoryAudit{}
	replay := &memoryReplay{seen: map[string]time.Time{}}
	authority, err := NewAuthority(engineKey, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]ed25519.PublicKey{"spiffe://brick/shared-adapter": callerKey.Public().(ed25519.PublicKey)}, audit, replay, fixedClock{now})
	if err != nil {
		t.Fatalf("NewAuthority() error = %v", err)
	}
	return fixture{now: now, callerKey: callerKey, engineKey: engineKey, audit: audit, replay: replay, authority: authority}
}

func (f fixture) request() Request {
	return Request{
		Schema: Schema, RequestID: "11111111-1111-4111-8111-111111111111", Action: ActionCreate,
		IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(5 * time.Minute), CallerSPIFFEID: "spiffe://brick/shared-adapter",
		PolicyID: "policy-shared-tenant", PolicyDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Profile: ProfileSharedTenant, CageID: "cage-tenant-a", HostIdentity: "host-staging-a",
		ResourcePolicy:           ResourcePolicy{CPUQuotaMilli: 500, MemoryMaxBytes: 1 << 30, PidsMax: 64, IOWeight: 100},
		MountPolicy:              MountPolicy{BaseRoot: "/srv/brick-cages/tenant-a", Mounts: []Mount{{Source: "/usr/bin", Destination: "/runtime/bin", ReadOnly: true}}, MandatoryLayers: append([]string(nil), mandatoryLayers...)},
		NetworkPolicy:            NetworkPolicy{Mode: "defaultDeny", AllowedEndpoints: []string{"https://api.example.test"}},
		ExecutableManifestDigest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", AuditTarget: "audit://host-isolation-ledger",
	}
}

func signedRequest(t *testing.T, f fixture) Request {
	t.Helper()
	req := f.request()
	if err := SignRequest(&req, f.callerKey); err != nil {
		t.Fatalf("SignRequest() error = %v", err)
	}
	return req
}

func TestAuthorizeValidRequestSignsAttestation(t *testing.T) {
	f := newFixture(t)
	attestation, err := f.authority.Authorize(signedRequest(t, f))
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if err := VerifyAttestation(attestation, f.engineKey.Public().(ed25519.PublicKey), f.now); err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if attestation.MonotonicSequence != 1 || attestation.ExpiresAt.After(f.now.Add(maxAttestationValidity)) || f.audit.events != 1 {
		t.Fatalf("unexpected attestation/audit result: %+v events=%d", attestation, f.audit.events)
	}
}

func TestAuthorizeRejectsReplayBeforeSecondAttestation(t *testing.T) {
	f := newFixture(t)
	req := signedRequest(t, f)
	if _, err := f.authority.Authorize(req); err != nil {
		t.Fatalf("first Authorize() error = %v", err)
	}
	if _, err := f.authority.Authorize(req); !errors.Is(err, ErrDenied) {
		t.Fatalf("second Authorize() error = %v, want denial", err)
	}
}

func TestAuthorizeRejectsTamperedSignatureAndProtectedMount(t *testing.T) {
	t.Run("tampered signature", func(t *testing.T) {
		f := newFixture(t)
		req := signedRequest(t, f)
		req.CageID = "cage-tampered-a"
		if _, err := f.authority.Authorize(req); !errors.Is(err, ErrDenied) {
			t.Fatalf("Authorize() error = %v, want denial", err)
		}
	})
	t.Run("protected mount", func(t *testing.T) {
		f := newFixture(t)
		req := f.request()
		req.MountPolicy.Mounts[0].Source = "/opt/brick/bin"
		if err := SignRequest(&req, f.callerKey); err != nil {
			t.Fatal(err)
		}
		if _, err := f.authority.Authorize(req); !errors.Is(err, ErrDenied) {
			t.Fatalf("Authorize() error = %v, want denial", err)
		}
	})
}

func TestAuthorizeFailsClosedForAuditReplayAndStaleTime(t *testing.T) {
	t.Run("audit failure", func(t *testing.T) {
		f := newFixture(t)
		f.audit.fail = true
		if _, err := f.authority.Authorize(signedRequest(t, f)); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Authorize() error = %v, want unavailable", err)
		}
	})
	t.Run("replay ledger failure", func(t *testing.T) {
		f := newFixture(t)
		f.replay.fail = true
		if _, err := f.authority.Authorize(signedRequest(t, f)); !errors.Is(err, ErrDenied) {
			t.Fatalf("Authorize() error = %v, want denial", err)
		}
	})
	t.Run("expired request", func(t *testing.T) {
		f := newFixture(t)
		req := f.request()
		req.ExpiresAt = f.now.Add(-time.Second)
		if err := SignRequest(&req, f.callerKey); err != nil {
			t.Fatal(err)
		}
		if _, err := f.authority.Authorize(req); !errors.Is(err, ErrDenied) {
			t.Fatalf("Authorize() error = %v, want denial", err)
		}
	})
}

func TestNewAuthorityRejectsIncompleteDependencies(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	if _, err := NewAuthority(key, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil, &memoryAudit{}, &memoryReplay{seen: map[string]time.Time{}}, fixedClock{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewAuthority() error = %v, want unavailable", err)
	}
}
