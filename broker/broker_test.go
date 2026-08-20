package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/brick/host-isolation/lifecycle"
)

type phase2Clock struct {
	mu   sync.Mutex
	now  time.Time
	fail bool
}

func (c *phase2Clock) Now() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return time.Time{}, errors.New("clock unavailable")
	}
	return c.now, nil
}

type authorityClock struct{ clock *phase2Clock }

func (c authorityClock) Now() time.Time {
	now, _ := c.clock.Now()
	return now
}

type auditEvent struct{ outcome, reason string }

type phase2Audit struct {
	mu     sync.Mutex
	fail   bool
	events []auditEvent
}

func (a *phase2Audit) RecordEvent(_ string, _ string, outcome, _ string, metadata map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, auditEvent{outcome: outcome, reason: stringValue(metadata["reasonCode"])})
	if a.fail {
		return errors.New("audit unavailable")
	}
	return nil
}

func (a *phase2Audit) hasReason(reason string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, event := range a.events {
		if event.reason == reason {
			return true
		}
	}
	return false
}

type phase2Preflight struct{ err error }

func (p *phase2Preflight) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return p.err
}

type brokerFixture struct {
	t                 *testing.T
	now               time.Time
	clock             *phase2Clock
	audit             *phase2Audit
	preflight         *phase2Preflight
	broker            *Broker
	callerKey         ed25519.PrivateKey
	callerIdentity    string
	engineKey         ed25519.PrivateKey
	rootPool          *x509.CertPool
	clientCertificate tls.Certificate
	socketPath        string
	cancel            context.CancelFunc
	done              <-chan error
}

func newBrokerFixture(t *testing.T, rate RateLimit) *brokerFixture {
	t.Helper()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	clock := &phase2Clock{now: now}
	dir, err := os.MkdirTemp("/tmp", "brk2-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	ledger, err := NewFileReplayLedger(FileReplayLedgerConfig{Path: filepath.Join(dir, "replay-ledger.json"), OwnerUID: uid, Clock: clock, MaxEntries: 100, MaxLedgerBytes: 32 * 1024})
	if err != nil {
		t.Fatalf("NewFileReplayLedger() error = %v", err)
	}
	callerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	engineKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	identity := "spiffe://brick/shared-adapter"
	audit := &phase2Audit{}
	authority, err := lifecycle.NewAuthority(engineKey, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]ed25519.PublicKey{identity: callerKey.Public().(ed25519.PublicKey)}, audit, ledger, fixedLifecycleClock{now})
	if err != nil {
		t.Fatalf("NewAuthority() error = %v", err)
	}
	serverTLS, clientTLS, rootPool := testTLS(t, identity)
	preflight := &phase2Preflight{}
	socketPath := filepath.Join(dir, "broker.sock")
	instance, err := New(Config{
		SocketPath: socketPath, SocketOwnerUID: uid, SocketMode: 0o600, AllowedPeerUIDs: []uint32{uid}, AllowedSPIFFEIDs: []string{identity}, TLSConfig: serverTLS,
		Authority: authority, Audit: audit, Preflight: preflight, Clock: clock, RateLimit: rate, MaxRequestBytes: 8 * 1024, MaxResponseBytes: 8 * 1024, RequestTimeout: 5 * time.Second, MaxConcurrentConnections: 8,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx) }()
	waitForSocket(t, socketPath)
	return &brokerFixture{t: t, now: now, clock: clock, audit: audit, preflight: preflight, broker: instance, callerKey: callerKey, callerIdentity: identity, engineKey: engineKey, rootPool: rootPool, clientCertificate: clientTLS.Certificates[0], socketPath: socketPath, cancel: cancel, done: done}
}

type fixedLifecycleClock struct{ now time.Time }

func (c fixedLifecycleClock) Now() time.Time { return c.now }

func (f *brokerFixture) close() {
	f.t.Helper()
	f.cancel()
	select {
	case err := <-f.done:
		if err != nil {
			f.t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		f.t.Fatal("Serve() did not stop after cancellation")
	}
}

func (f *brokerFixture) request(id string) lifecycle.Request {
	f.t.Helper()
	req := lifecycle.Request{
		Schema: lifecycle.Schema, RequestID: id, Action: lifecycle.ActionCreate, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(5 * time.Minute), CallerSPIFFEID: f.callerIdentity, PolicyID: "policy-shared-tenant", PolicyDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Profile: lifecycle.ProfileSharedTenant, CageID: "cage-tenant-a", HostIdentity: "host-staging-a",
		ResourcePolicy: lifecycle.ResourcePolicy{CPUQuotaMilli: 500, MemoryMaxBytes: 1 << 30, PidsMax: 64, IOWeight: 100},
		MountPolicy:    lifecycle.MountPolicy{BaseRoot: "/srv/brick-cages/tenant-a", Mounts: []lifecycle.Mount{{Source: "/usr/bin", Destination: "/runtime/bin", ReadOnly: true}}, MandatoryLayers: mandatoryLayers()},
		NetworkPolicy:  lifecycle.NetworkPolicy{Mode: "defaultDeny", AllowedEndpoints: []string{"https://api.example.test"}}, ExecutableManifestDigest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", AuditTarget: "audit://host-isolation-ledger",
	}
	if err := lifecycle.SignRequest(&req, f.callerKey); err != nil {
		f.t.Fatal(err)
	}
	return req
}

func (f *brokerFixture) roundTrip(request lifecycle.Request) (ResponseEnvelope, error) {
	f.t.Helper()
	connection, err := net.DialTimeout("unix", f.socketPath, 3*time.Second)
	if err != nil {
		return ResponseEnvelope{}, err
	}
	defer connection.Close()
	client := tls.Client(connection, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.rootPool, ServerName: "broker.test", Certificates: []tls.Certificate{f.clientCertificate}})
	defer client.Close()
	if err := client.Handshake(); err != nil {
		return ResponseEnvelope{}, err
	}
	payload, err := json.Marshal(RequestEnvelope{Protocol: Protocol, Request: request})
	if err != nil {
		return ResponseEnvelope{}, err
	}
	if err := writeFrame(client, payload); err != nil {
		return ResponseEnvelope{}, err
	}
	responsePayload, err := readFrame(client, 8*1024)
	if err != nil {
		return ResponseEnvelope{}, err
	}
	var response ResponseEnvelope
	if err := strictDecode(responsePayload, &response); err != nil {
		return ResponseEnvelope{}, err
	}
	return response, nil
}

func TestBrokerAuthorizesExactAuthenticatedIdentity(t *testing.T) {
	f := newBrokerFixture(t, RateLimit{Capacity: 10, RefillInterval: time.Second})
	defer f.close()
	response, err := f.roundTrip(f.request("11111111-1111-4111-8111-111111111111"))
	if err != nil {
		t.Fatalf("roundTrip() error = %v", err)
	}
	if response.Protocol != Protocol || response.Status != "authorized" || response.Attestation == nil {
		t.Fatalf("unexpected response: %+v", response)
	}
	if err := lifecycle.VerifyAttestation(*response.Attestation, f.engineKey.Public().(ed25519.PublicKey), f.now); err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	info, err := os.Lstat(f.socketPath)
	if err != nil || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("insecure socket state: info=%v err=%v", info, err)
	}
}

func TestBrokerDeniesIdentityMismatchReplayRateAndPreflightFailure(t *testing.T) {
	t.Run("spiffe identity mismatch", func(t *testing.T) {
		f := newBrokerFixture(t, RateLimit{Capacity: 10, RefillInterval: time.Second})
		defer f.close()
		req := f.request("22222222-2222-4222-8222-222222222222")
		req.CallerSPIFFEID = "spiffe://brick/dedicated-adapter"
		response, err := f.roundTrip(req)
		if err != nil || response.Status != "denied" || response.ReasonCode != "spiffe_request_identity_mismatch" {
			t.Fatalf("response=%+v err=%v", response, err)
		}
	})
	t.Run("replayed request", func(t *testing.T) {
		f := newBrokerFixture(t, RateLimit{Capacity: 10, RefillInterval: time.Second})
		defer f.close()
		req := f.request("33333333-3333-4333-8333-333333333333")
		if response, err := f.roundTrip(req); err != nil || response.Status != "authorized" {
			t.Fatalf("first response=%+v err=%v", response, err)
		}
		response, err := f.roundTrip(req)
		if err != nil || response.Status != "denied" || response.ReasonCode != "replayed_request" {
			t.Fatalf("second response=%+v err=%v", response, err)
		}
	})
	t.Run("rate exhausted", func(t *testing.T) {
		f := newBrokerFixture(t, RateLimit{Capacity: 1, RefillInterval: time.Hour})
		defer f.close()
		if response, err := f.roundTrip(f.request("44444444-4444-4444-8444-444444444444")); err != nil || response.Status != "authorized" {
			t.Fatalf("first response=%+v err=%v", response, err)
		}
		response, err := f.roundTrip(f.request("55555555-5555-4555-8555-555555555555"))
		if err != nil || response.Status != "denied" || response.ReasonCode != "rate_limit_exhausted" {
			t.Fatalf("second response=%+v err=%v", response, err)
		}
	})
	t.Run("preflight unavailable", func(t *testing.T) {
		f := newBrokerFixture(t, RateLimit{Capacity: 10, RefillInterval: time.Second})
		defer f.close()
		f.preflight.err = errors.New("preflight missing")
		response, err := f.roundTrip(f.request("66666666-6666-4666-8666-666666666666"))
		if err != nil || response.Status != "unavailable" || response.ReasonCode != "host_preflight_unavailable" {
			t.Fatalf("response=%+v err=%v", response, err)
		}
	})
}

func TestBrokerRejectsOversizedFramesAndAuditFailure(t *testing.T) {
	t.Run("oversized frame", func(t *testing.T) {
		f := newBrokerFixture(t, RateLimit{Capacity: 10, RefillInterval: time.Second})
		defer f.close()
		connection, err := net.DialTimeout("unix", f.socketPath, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		client := tls.Client(connection, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.rootPool, ServerName: "broker.test", Certificates: []tls.Certificate{f.clientCertificate}})
		defer client.Close()
		if err := client.Handshake(); err != nil {
			t.Fatal(err)
		}
		if err := writeFrame(client, bytes.Repeat([]byte{'a'}, 9*1024)); err != nil {
			t.Fatal(err)
		}
		payload, err := readFrame(client, 8*1024)
		if err != nil {
			t.Fatal(err)
		}
		var response ResponseEnvelope
		if err := strictDecode(payload, &response); err != nil || response.ReasonCode != "malformed_or_oversized_frame" || !f.audit.hasReason("malformed_or_oversized_frame") {
			t.Fatalf("response=%+v err=%v", response, err)
		}
	})
	t.Run("audit failure closes without authorizing", func(t *testing.T) {
		f := newBrokerFixture(t, RateLimit{Capacity: 10, RefillInterval: time.Second})
		defer f.close()
		f.audit.fail = true
		if _, err := f.roundTrip(f.request("77777777-7777-4777-8777-777777777777")); err == nil {
			t.Fatal("roundTrip() succeeded while audit sink was unavailable")
		}
	})
}

func TestFileReplayLedgerIsDurableAndRejectsUnsafeState(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	clock := &phase2Clock{now: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	path := filepath.Join(dir, "ledger.json")
	config := FileReplayLedgerConfig{Path: path, OwnerUID: uint32(os.Getuid()), Clock: clock, MaxEntries: 2, MaxLedgerBytes: 4096}
	ledger, err := NewFileReplayLedger(config)
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := ledger.Claim("request-a", clock.now.Add(time.Minute)); err != nil || !claimed {
		t.Fatalf("Claim() = %t, %v", claimed, err)
	}
	reopened, err := NewFileReplayLedger(config)
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := reopened.Claim("request-a", clock.now.Add(time.Minute)); err != nil || claimed {
		t.Fatalf("durable replay Claim() = %t, %v", claimed, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Claim("request-b", clock.now.Add(time.Minute)); !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatalf("Claim() error = %v, want ledger unavailable", err)
	}
}

func TestNewFailsClosedForMissingTLSAndUnsafeDirectory(t *testing.T) {
	instance, err := New(Config{})
	if instance != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("New() = %v, %v; want unavailable", instance, err)
	}
	f := newBrokerFixture(t, RateLimit{Capacity: 10, RefillInterval: time.Second})
	f.close()
	if err := os.Chmod(filepath.Dir(f.socketPath), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := f.broker.Serve(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Serve() error = %v, want unavailable", err)
	}
}

func mandatoryLayers() []string {
	return []string{"auditBeforeResponse", "callerAuthentication", "capabilityDrop", "cgroupV2", "defaultDenyEgress", "environmentSanitization", "executableManifest", "immutableBaseRoot", "ipcNamespace", "mountNamespace", "networkNamespace", "noNewPrivileges", "pidNamespace", "protectedPathExclusion", "replayProtection", "seccomp", "userNamespace", "utsNamespace"}
}

func testTLS(t *testing.T, identity string) (*tls.Config, *tls.Config, *x509.CertPool) {
	t.Helper()
	rootKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Brick Phase 2 Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	serverCert := issueCertificate(t, root, rootKey, 2, "broker.test", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	clientCert := issueCertificate(t, root, rootKey, 3, "shared-adapter", []*url.URL{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	client := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "broker.test", Certificates: []tls.Certificate{clientCert}}
	return server, client, pool
}

func issueCertificate(t *testing.T, root *x509.Certificate, rootKey ed25519.PrivateKey, serial int64, name string, uris []*url.URL, usages []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(serial + 3)}, ed25519.SeedSize))
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, URIs: uris, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, root.Raw}, PrivateKey: key}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("broker socket %q did not appear", path)
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}
