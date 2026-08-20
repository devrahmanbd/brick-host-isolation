package broker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/brick/host-isolation/lifecycle"
)

const Protocol = "brick.host-isolation.broker.v1"

var (
	ErrDenied      = errors.New("broker request denied")
	ErrUnavailable = errors.New("broker unavailable")
)

type Authorizer interface {
	Authorize(lifecycle.Request) (lifecycle.Attestation, error)
}

type HostPreflight interface {
	Check(context.Context) error
}

type RateLimit struct {
	Capacity       int
	RefillInterval time.Duration
}

type Config struct {
	SocketPath               string
	SocketOwnerUID           uint32
	SocketMode               os.FileMode
	AllowedPeerUIDs          []uint32
	AllowedSPIFFEIDs         []string
	TLSConfig                *tls.Config
	Authority                Authorizer
	Audit                    lifecycle.AuditSink
	Preflight                HostPreflight
	Clock                    Clock
	RateLimit                RateLimit
	MaxRequestBytes          uint32
	MaxResponseBytes         uint32
	RequestTimeout           time.Duration
	MaxConcurrentConnections int
}

type RequestEnvelope struct {
	Protocol string            `json:"protocol"`
	Request  lifecycle.Request `json:"request"`
}

type ResponseEnvelope struct {
	Protocol    string                 `json:"protocol"`
	Status      string                 `json:"status"`
	ReasonCode  string                 `json:"reasonCode,omitempty"`
	Attestation *lifecycle.Attestation `json:"attestation,omitempty"`
}

// Broker listens only on a configured Unix-domain socket. It performs local
// peer-UID verification, TLS 1.3 mutual authentication, exact SPIFFE binding,
// bounded framing, per-identity rate limiting, host preflight, and Phase 1
// authorization. It never creates a cage or runs a workload process.
type Broker struct {
	config            Config
	trustedIdentities map[string]struct{}
	allowedUIDs       map[uint32]struct{}
	limiter           *identityLimiter
}

type identityLimiter struct {
	mu      sync.Mutex
	entries map[string]bucket
	limit   RateLimit
}

type bucket struct {
	tokens float64
	last   time.Time
}

func New(config Config) (*Broker, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	identities := make(map[string]struct{}, len(config.AllowedSPIFFEIDs))
	for _, identity := range config.AllowedSPIFFEIDs {
		identities[identity] = struct{}{}
	}
	uids := make(map[uint32]struct{}, len(config.AllowedPeerUIDs))
	for _, uid := range config.AllowedPeerUIDs {
		uids[uid] = struct{}{}
	}
	config.TLSConfig = config.TLSConfig.Clone()
	return &Broker{config: config, trustedIdentities: identities, allowedUIDs: uids, limiter: &identityLimiter{entries: make(map[string]bucket, len(identities)), limit: config.RateLimit}}, nil
}

func (b *Broker) Serve(ctx context.Context) error {
	if b == nil {
		return fmt.Errorf("%w: nil broker", ErrUnavailable)
	}
	listener, err := b.listen()
	if err != nil {
		return err
	}
	defer b.closeListener(listener)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-done:
		}
	}()
	defer close(done)
	semaphore := make(chan struct{}, b.config.MaxConcurrentConnections)
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("%w: socket accept failure", ErrUnavailable)
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				b.serveConnection(ctx, connection)
			}()
		default:
			b.record("unidentified", "connection", "denied", "unidentified", "connection_capacity_exhausted")
			connection.Close()
		}
	}
}

func (b *Broker) serveConnection(parent context.Context, connection *net.UnixConn) {
	defer connection.Close()
	uid, err := peerUID(connection)
	if err != nil {
		b.record("unidentified", "connection", "denied", "unidentified", "peer_credential_unavailable")
		return
	}
	if _, allowed := b.allowedUIDs[uid]; !allowed {
		b.record("unix-uid:"+strconv.FormatUint(uint64(uid), 10), "connection", "denied", "unidentified", "unexpected_peer_uid")
		return
	}
	deadline, err := b.deadline()
	if err != nil {
		b.record("unidentified", "connection", "denied", "unidentified", "clock_unavailable")
		return
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return
	}
	secured := tls.Server(connection, b.config.TLSConfig)
	if err := secured.HandshakeContext(parent); err != nil {
		b.record("unix-uid:"+strconv.FormatUint(uint64(uid), 10), "connection", "denied", "unidentified", "mutual_tls_failed")
		return
	}
	identity, err := b.verifyPeerIdentity(secured.ConnectionState())
	if err != nil {
		b.record("unix-uid:"+strconv.FormatUint(uint64(uid), 10), "connection", "denied", "unidentified", "untrusted_spiffe_identity")
		return
	}
	if !b.limiter.allow(identity, b.config.Clock) {
		b.fail(secured, identity, "connection", "unidentified", "rate_limit_exhausted", "denied")
		return
	}
	payload, err := readFrame(secured, b.config.MaxRequestBytes)
	if err != nil {
		b.fail(secured, identity, "connection", "unidentified", "malformed_or_oversized_frame", "denied")
		return
	}
	var envelope RequestEnvelope
	if err := strictDecode(payload, &envelope); err != nil || envelope.Protocol != Protocol {
		b.fail(secured, identity, "connection", "unidentified", "malformed_envelope", "denied")
		return
	}
	if envelope.Request.CallerSPIFFEID != identity {
		b.fail(secured, identity, string(envelope.Request.Action), envelope.Request.CageID, "spiffe_request_identity_mismatch", "denied")
		return
	}
	requestContext, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	if err := b.config.Preflight.Check(requestContext); err != nil {
		b.fail(secured, identity, string(envelope.Request.Action), envelope.Request.CageID, "host_preflight_unavailable", "unavailable")
		return
	}
	attestation, err := b.config.Authority.Authorize(envelope.Request)
	if err != nil {
		status, code := authorizationResult(err)
		if b.record(identity, string(envelope.Request.Action), status, envelope.Request.CageID, code) != nil {
			return
		}
		b.writeResponse(secured, ResponseEnvelope{Protocol: Protocol, Status: status, ReasonCode: code})
		return
	}
	if b.record(identity, string(envelope.Request.Action), "authorized", envelope.Request.CageID, "authorized") != nil {
		return
	}
	b.writeResponse(secured, ResponseEnvelope{Protocol: Protocol, Status: "authorized", Attestation: &attestation})
}

func (b *Broker) fail(connection net.Conn, actor, action, resource, reason, status string) {
	if b.record(actor, action, "denied", resource, reason) != nil {
		return
	}
	b.writeResponse(connection, ResponseEnvelope{Protocol: Protocol, Status: status, ReasonCode: reason})
}

func (b *Broker) writeResponse(writer io.Writer, response ResponseEnvelope) error {
	payload, err := json.Marshal(response)
	if err != nil || len(payload) == 0 || uint32(len(payload)) > b.config.MaxResponseBytes {
		return fmt.Errorf("%w: invalid response", ErrUnavailable)
	}
	return writeFrame(writer, payload)
}

func (b *Broker) record(actor, action, outcome, resource, reason string) error {
	if b.config.Audit == nil {
		return fmt.Errorf("%w: audit unavailable", ErrUnavailable)
	}
	return b.config.Audit.RecordEvent(actor, action, outcome, resource, map[string]any{"reasonCode": reason, "protocol": Protocol})
}

func (b *Broker) deadline() (time.Time, error) {
	now, err := b.config.Clock.Now()
	if err != nil || now.IsZero() {
		return time.Time{}, fmt.Errorf("%w: clock unavailable", ErrUnavailable)
	}
	return now.UTC().Add(b.config.RequestTimeout), nil
}

func (b *Broker) listen() (*net.UnixListener, error) {
	if err := b.checkSocketDirectory(); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(b.config.SocketPath); err == nil {
		if err := b.validateSocket(info); err != nil {
			return nil, err
		}
		if err := os.Remove(b.config.SocketPath); err != nil {
			return nil, fmt.Errorf("%w: stale socket removal failed", ErrUnavailable)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: socket path inspection failed", ErrUnavailable)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: b.config.SocketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("%w: socket bind failed", ErrUnavailable)
	}
	if err := os.Chmod(b.config.SocketPath, b.config.SocketMode); err != nil {
		listener.Close()
		return nil, fmt.Errorf("%w: socket permissions failed", ErrUnavailable)
	}
	info, err := os.Lstat(b.config.SocketPath)
	if err != nil || b.validateSocket(info) != nil {
		listener.Close()
		return nil, fmt.Errorf("%w: unsafe bound socket", ErrUnavailable)
	}
	return listener, nil
}

func (b *Broker) closeListener(listener *net.UnixListener) {
	listener.Close()
	if info, err := os.Lstat(b.config.SocketPath); err == nil && b.validateSocket(info) == nil {
		os.Remove(b.config.SocketPath)
	}
}

func (b *Broker) checkSocketDirectory() error {
	info, err := os.Lstat(filepath.Dir(b.config.SocketPath))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: unsafe socket directory", ErrUnavailable)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != b.config.SocketOwnerUID || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: insecure socket directory", ErrUnavailable)
	}
	return nil
}

func (b *Broker) validateSocket(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != b.config.SocketOwnerUID || info.Mode().Perm() != b.config.SocketMode || info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("%w: insecure socket", ErrUnavailable)
	}
	return nil
}

func (b *Broker) verifyPeerIdentity(state tls.ConnectionState) (string, error) {
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("%w: unverified certificate", ErrDenied)
	}
	for _, identity := range state.PeerCertificates[0].URIs {
		if identity == nil {
			continue
		}
		value := identity.String()
		if _, permitted := b.trustedIdentities[value]; permitted {
			return value, nil
		}
	}
	return "", fmt.Errorf("%w: untrusted workload identity", ErrDenied)
}

func (l *identityLimiter) allow(identity string, clock Clock) bool {
	now, err := clock.Now()
	if err != nil || now.IsZero() {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, found := l.entries[identity]
	if !found {
		entry = bucket{tokens: float64(l.limit.Capacity), last: now.UTC()}
	}
	elapsed := now.UTC().Sub(entry.last)
	if elapsed < 0 {
		return false
	}
	entry.tokens = min(float64(l.limit.Capacity), entry.tokens+elapsed.Seconds()/l.limit.RefillInterval.Seconds())
	entry.last = now.UTC()
	if entry.tokens < 1 {
		l.entries[identity] = entry
		return false
	}
	entry.tokens--
	l.entries[identity] = entry
	return true
}

func validateConfig(config Config) error {
	if config.Authority == nil || config.Audit == nil || config.Preflight == nil || config.Clock == nil || config.TLSConfig == nil {
		return fmt.Errorf("%w: missing mandatory dependency", ErrUnavailable)
	}
	if !filepath.IsAbs(config.SocketPath) || filepath.Clean(config.SocketPath) != config.SocketPath || filepath.Base(config.SocketPath) == "." || len(config.SocketPath) > 100 {
		return fmt.Errorf("%w: unsafe socket path", ErrUnavailable)
	}
	if config.SocketMode != 0o600 && config.SocketMode != 0o660 {
		return fmt.Errorf("%w: invalid socket mode", ErrUnavailable)
	}
	if len(config.AllowedPeerUIDs) == 0 || len(config.AllowedSPIFFEIDs) == 0 || config.MaxRequestBytes < 256 || config.MaxRequestBytes > 65536 || config.MaxResponseBytes < 256 || config.MaxResponseBytes > 16384 || config.RequestTimeout < time.Second || config.RequestTimeout > time.Minute || config.MaxConcurrentConnections < 1 || config.MaxConcurrentConnections > 1024 || config.RateLimit.Capacity < 1 || config.RateLimit.Capacity > 10000 || config.RateLimit.RefillInterval < time.Millisecond || config.RateLimit.RefillInterval > time.Hour {
		return fmt.Errorf("%w: invalid bounds", ErrUnavailable)
	}
	if config.TLSConfig.MinVersion < tls.VersionTLS13 || config.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || config.TLSConfig.ClientCAs == nil || len(config.TLSConfig.Certificates) == 0 {
		return fmt.Errorf("%w: invalid mutual TLS configuration", ErrUnavailable)
	}
	seenIdentities := map[string]struct{}{}
	for _, identity := range config.AllowedSPIFFEIDs {
		if !validSPIFFE(identity) {
			return fmt.Errorf("%w: invalid SPIFFE identity", ErrUnavailable)
		}
		if _, exists := seenIdentities[identity]; exists {
			return fmt.Errorf("%w: duplicate SPIFFE identity", ErrUnavailable)
		}
		seenIdentities[identity] = struct{}{}
	}
	seenUIDs := map[uint32]struct{}{}
	for _, uid := range config.AllowedPeerUIDs {
		if _, exists := seenUIDs[uid]; exists {
			return fmt.Errorf("%w: duplicate peer UID", ErrUnavailable)
		}
		seenUIDs[uid] = struct{}{}
	}
	return nil
}

func validSPIFFE(value string) bool {
	u, err := url.ParseRequestURI(value)
	return err == nil && u.Scheme == "spiffe" && u.Host != "" && strings.HasPrefix(u.Path, "/") && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *syscall.Ucred
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		credential, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || controlErr != nil || credential == nil {
		return 0, fmt.Errorf("peer credential unavailable")
	}
	return credential.Uid, nil
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
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > int(^uint32(0)) {
		return fmt.Errorf("invalid frame payload")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func strictDecode(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func authorizationResult(err error) (string, string) {
	var decision *lifecycle.DecisionError
	if errors.As(err, &decision) {
		return "denied", decision.Code
	}
	if errors.Is(err, lifecycle.ErrUnavailable) {
		return "unavailable", "authority_unavailable"
	}
	return "unavailable", "authorization_unavailable"
}

func min(left, right float64) float64 {
	if left < right {
		return left
	}
	return right
}
