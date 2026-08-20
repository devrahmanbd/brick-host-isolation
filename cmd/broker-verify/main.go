package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/brick/host-isolation/broker"
	"github.com/brick/host-isolation/lifecycle"
)

type clock struct{ now time.Time }

func (c clock) Now() (time.Time, error) { return c.now, nil }

type lifecycleClock struct{ now time.Time }

func (c lifecycleClock) Now() time.Time { return c.now }

type audit struct{}

func (audit) RecordEvent(string, string, string, string, map[string]any) error { return nil }

type preflight struct{}

func (preflight) Check(context.Context) error { return nil }

func main() {
	if err := verify(); err != nil {
		fmt.Fprintf(os.Stderr, "host-isolation broker verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("host-isolation broker verification passed")
}

func verify() error {
	contract, err := os.ReadFile("contracts/brick-host-isolation-broker.v1.json")
	if err != nil {
		return fmt.Errorf("read broker contract: %w", err)
	}
	var shape struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(contract, &shape); err != nil || shape.Schema != broker.Protocol {
		return fmt.Errorf("invalid broker contract schema")
	}
	dir, err := os.MkdirTemp("/tmp", "brick-broker-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	localClock := clock{now: now}
	callerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	engineKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	identity := "spiffe://brick/shared-adapter"
	ledger, err := broker.NewFileReplayLedger(broker.FileReplayLedgerConfig{Path: filepath.Join(dir, "replay.json"), OwnerUID: uint32(os.Getuid()), Clock: localClock, MaxEntries: 16, MaxLedgerBytes: 4096})
	if err != nil {
		return err
	}
	authority, err := lifecycle.NewAuthority(engineKey, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]ed25519.PublicKey{identity: callerKey.Public().(ed25519.PublicKey)}, audit{}, ledger, lifecycleClock{now})
	if err != nil {
		return err
	}
	serverTLS, clientTLS, err := makeTLS(identity)
	if err != nil {
		return err
	}
	socketPath := filepath.Join(dir, "broker.sock")
	instance, err := broker.New(broker.Config{SocketPath: socketPath, SocketOwnerUID: uint32(os.Getuid()), SocketMode: 0o600, AllowedPeerUIDs: []uint32{uint32(os.Getuid())}, AllowedSPIFFEIDs: []string{identity}, TLSConfig: serverTLS, Authority: authority, Audit: audit{}, Preflight: preflight{}, Clock: localClock, RateLimit: broker.RateLimit{Capacity: 4, RefillInterval: time.Second}, MaxRequestBytes: 8192, MaxResponseBytes: 8192, RequestTimeout: 5 * time.Second, MaxConcurrentConnections: 2})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	if err := waitForSocket(socketPath); err != nil {
		return err
	}
	request := lifecycle.Request{Schema: lifecycle.Schema, RequestID: "11111111-1111-4111-8111-111111111111", Action: lifecycle.ActionCreate, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute), CallerSPIFFEID: identity, PolicyID: "policy-shared-tenant", PolicyDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Profile: lifecycle.ProfileSharedTenant, CageID: "cage-tenant-a", HostIdentity: "host-staging-a", ResourcePolicy: lifecycle.ResourcePolicy{CPUQuotaMilli: 500, MemoryMaxBytes: 1 << 30, PidsMax: 64, IOWeight: 100}, MountPolicy: lifecycle.MountPolicy{BaseRoot: "/srv/brick-cages/tenant-a", Mounts: []lifecycle.Mount{{Source: "/usr/bin", Destination: "/runtime/bin", ReadOnly: true}}, MandatoryLayers: mandatoryLayers()}, NetworkPolicy: lifecycle.NetworkPolicy{Mode: "defaultDeny", AllowedEndpoints: []string{"https://api.example.test"}}, ExecutableManifestDigest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", AuditTarget: "audit://host-isolation-ledger"}
	if err := lifecycle.SignRequest(&request, callerKey); err != nil {
		return err
	}
	connection, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	secured := tls.Client(connection, clientTLS)
	defer secured.Close()
	if err := secured.Handshake(); err != nil {
		return err
	}
	payload, err := json.Marshal(broker.RequestEnvelope{Protocol: broker.Protocol, Request: request})
	if err != nil {
		return err
	}
	if err := writeFrame(secured, payload); err != nil {
		return err
	}
	responsePayload, err := readFrame(secured, 8192)
	if err != nil {
		return err
	}
	var response broker.ResponseEnvelope
	if err := json.Unmarshal(responsePayload, &response); err != nil || response.Status != "authorized" || response.Attestation == nil {
		return fmt.Errorf("broker did not return authorization evidence")
	}
	return lifecycle.VerifyAttestation(*response.Attestation, engineKey.Public().(ed25519.PublicKey), now)
}

func makeTLS(identity string) (*tls.Config, *tls.Config, error) {
	rootKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Brick broker verifier CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		return nil, nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	server, err := issue(root, rootKey, 2, "broker.test", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		return nil, nil, err
	}
	uri, err := url.Parse(identity)
	if err != nil {
		return nil, nil, err
	}
	client, err := issue(root, rootKey, 3, "shared-adapter", []*url.URL{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err != nil {
		return nil, nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "broker.test", Certificates: []tls.Certificate{client}}, nil
}

func issue(root *x509.Certificate, rootKey ed25519.PrivateKey, serial int64, name string, uris []*url.URL, usages []x509.ExtKeyUsage) (tls.Certificate, error) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(serial + 3)}, ed25519.SeedSize))
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, URIs: uris, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, root, key.Public(), rootKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, root.Raw}, PrivateKey: key}, nil
}

func mandatoryLayers() []string {
	return []string{"auditBeforeResponse", "callerAuthentication", "capabilityDrop", "cgroupV2", "defaultDenyEgress", "environmentSanitization", "executableManifest", "immutableBaseRoot", "ipcNamespace", "mountNamespace", "networkNamespace", "noNewPrivileges", "pidNamespace", "protectedPathExclusion", "replayProtection", "seccomp", "userNamespace", "utsNamespace"}
}

func waitForSocket(path string) error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("broker socket did not appear")
}

func writeFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty frame")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	for _, segment := range [][]byte{header[:], payload} {
		for len(segment) > 0 {
			written, err := writer.Write(segment)
			if err != nil {
				return err
			}
			if written == 0 {
				return io.ErrShortWrite
			}
			segment = segment[written:]
		}
	}
	return nil
}

func readFrame(reader io.Reader, max uint32) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > max {
		return nil, fmt.Errorf("invalid frame length")
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(reader, payload)
	return payload, err
}
