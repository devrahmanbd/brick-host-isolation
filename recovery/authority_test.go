package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/brick/host-isolation/lifecycle"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type journal struct {
	events []Event
	fail   bool
}

func (j *journal) Append(event Event) error {
	if j.fail {
		return errors.New("journal unavailable")
	}
	j.events = append(j.events, event)
	return nil
}

type audit struct {
	fail  bool
	calls int
}

func (a *audit) RecordEvent(string, string, string, string, map[string]any) error {
	a.calls++
	if a.fail {
		return errors.New("audit unavailable")
	}
	return nil
}

type evidence struct {
	digest string
	fail   bool
	calls  int
}

func (e *evidence) Capture(context.Context, string, string) (string, error) {
	e.calls++
	if e.fail {
		return "", errors.New("capture unavailable")
	}
	return e.digest, nil
}

type controller struct {
	calls []string
	fail  string
}

func (c *controller) run(action string) error {
	c.calls = append(c.calls, action)
	if c.fail == action {
		return errors.New(action + " failure")
	}
	return nil
}
func (c *controller) Kill(context.Context, string) error            { return c.run("kill") }
func (c *controller) Freeze(context.Context, string) error          { return c.run("freeze") }
func (c *controller) WithdrawNetwork(context.Context, string) error { return c.run("withdrawNetwork") }
func (c *controller) Destroy(context.Context, string) error         { return c.run("destroy") }

type handoff struct {
	calls int
	fail  bool
}

func (h *handoff) Handoff(context.Context, string, string) error {
	h.calls++
	if h.fail {
		return errors.New("handoff failure")
	}
	return nil
}

type fixture struct {
	key        ed25519.PrivateKey
	journal    *journal
	audit      *audit
	evidence   *evidence
	controller *controller
	handoff    *handoff
	authority  *Authority
	now        time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	j, a, e, c, h := &journal{}, &audit{}, &evidence{digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, &controller{}, &handoff{}
	authority, err := NewAuthority(key, j, a, e, c, h, fixedClock{now})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{key, j, a, e, c, h, authority, now}
}
func (f fixture) request() Request {
	return Request{Schema: Schema, RecoveryID: "11111111-1111-4111-8111-111111111111", CageID: "cage-tenant-a", CallerSPIFFEID: "spiffe://brick/recovery", HostIdentity: "host-staging-a", PolicyDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ReasonCode: "anomaly"}
}

func TestSuspendAndRecoverOrdersKillFirstAndSignsEvidence(t *testing.T) {
	f := newFixture(t)
	value, err := f.authority.SuspendAndRecover(context.Background(), f.request())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := f.controller.calls, []string{"kill", "freeze", "withdrawNetwork", "destroy"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("controller order=%v want=%v", got, want)
	}
	if f.handoff.calls != 1 || len(f.journal.events) != 7 || f.audit.calls != 7 {
		t.Fatalf("incomplete evidence: events=%d audit=%d handoff=%d", len(f.journal.events), f.audit.calls, f.handoff.calls)
	}
	if err := VerifyAttestation(value, f.key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	for _, event := range f.journal.events {
		if err := VerifyEvent(event, f.key.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
	}
}
func TestSuspendAndRecoverStopsAfterFailedStepAndRecordsFailure(t *testing.T) {
	f := newFixture(t)
	f.controller.fail = "freeze"
	if _, err := f.authority.SuspendAndRecover(context.Background(), f.request()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error=%v", err)
	}
	if got, want := f.controller.calls, []string{"kill", "freeze"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("calls=%v", got)
	}
	if last := f.journal.events[len(f.journal.events)-1]; last.Action != "freeze" || last.Outcome != "failed" {
		t.Fatalf("last event=%+v", last)
	}
}
func TestSuspendAndRecoverFailsBeforeSideEffectsWhenJournalOrAuditUnavailable(t *testing.T) {
	t.Run("journal", func(t *testing.T) {
		f := newFixture(t)
		f.journal.fail = true
		if _, err := f.authority.SuspendAndRecover(context.Background(), f.request()); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		if len(f.controller.calls) != 0 {
			t.Fatal("controller invoked")
		}
	})
	t.Run("audit", func(t *testing.T) {
		f := newFixture(t)
		f.audit.fail = true
		if _, err := f.authority.SuspendAndRecover(context.Background(), f.request()); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		if len(f.controller.calls) != 0 {
			t.Fatal("controller invoked")
		}
	})
}
func TestSuspendAndRecoverRejectsMalformedOrCancelledRequest(t *testing.T) {
	f := newFixture(t)
	bad := f.request()
	bad.CageID = "../../unsafe"
	if _, err := f.authority.SuspendAndRecover(context.Background(), bad); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.authority.SuspendAndRecover(ctx, f.request()); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if len(f.controller.calls) != 0 {
		t.Fatal("controller invoked")
	}
}
func TestSignedEvidenceRejectsTampering(t *testing.T) {
	f := newFixture(t)
	value, err := f.authority.SuspendAndRecover(context.Background(), f.request())
	if err != nil {
		t.Fatal(err)
	}
	value.EvidenceDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := VerifyAttestation(value, f.key.Public().(ed25519.PublicKey)); !errors.Is(err, ErrDenied) {
		t.Fatalf("tamper accepted: %v", err)
	}
}

var _ lifecycle.AuditSink = (*audit)(nil)
