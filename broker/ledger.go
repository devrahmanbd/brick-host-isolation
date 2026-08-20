// Package broker provides the local, root-owned authorization boundary between
// edition adapters and future privileged host-isolation lifecycle operations.
package broker

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

var ErrLedgerUnavailable = errors.New("broker replay ledger unavailable")

// Clock is deliberately fallible so a clock failure cannot silently become an
// authorization decision based on zero, stale, or locally fabricated time.
type Clock interface {
	Now() (time.Time, error)
}

type SystemClock struct{}

func (SystemClock) Now() (time.Time, error) { return time.Now().UTC(), nil }

type FileReplayLedgerConfig struct {
	Path           string
	OwnerUID       uint32
	Clock          Clock
	MaxEntries     int
	MaxLedgerBytes int64
}

// FileReplayLedger is a compact, durable, cross-process single-use request
// ledger. A secure parent directory and explicit owner are mandatory.
type FileReplayLedger struct {
	path           string
	ownerUID       uint32
	clock          Clock
	maxEntries     int
	maxLedgerBytes int64
}

type replayRecord struct {
	RequestID string    `json:"requestId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func NewFileReplayLedger(config FileReplayLedgerConfig) (*FileReplayLedger, error) {
	if config.Clock == nil || config.MaxEntries < 1 || config.MaxLedgerBytes < 1024 {
		return nil, fmt.Errorf("%w: incomplete configuration", ErrLedgerUnavailable)
	}
	if !filepath.IsAbs(config.Path) || filepath.Clean(config.Path) != config.Path || strings.Contains(filepath.Base(config.Path), "/") || config.Path == "/" {
		return nil, fmt.Errorf("%w: unsafe ledger path", ErrLedgerUnavailable)
	}
	ledger := &FileReplayLedger{path: config.Path, ownerUID: config.OwnerUID, clock: config.Clock, maxEntries: config.MaxEntries, maxLedgerBytes: config.MaxLedgerBytes}
	if err := ledger.checkParent(); err != nil {
		return nil, err
	}
	return ledger, nil
}

// Claim implements lifecycle.ReplayLedger. It writes a complete new ledger and
// fsyncs the data and directory before success is returned.
func (l *FileReplayLedger) Claim(requestID string, expiresAt time.Time) (bool, error) {
	if l == nil || l.clock == nil || requestID == "" || expiresAt.IsZero() {
		return false, fmt.Errorf("%w: invalid claim input", ErrLedgerUnavailable)
	}
	now, err := l.clock.Now()
	if err != nil || now.IsZero() || !expiresAt.After(now.UTC()) {
		return false, fmt.Errorf("%w: clock unavailable or stale claim", ErrLedgerUnavailable)
	}
	if err := l.checkParent(); err != nil {
		return false, err
	}
	lock, err := l.openOwnedFile(l.path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return false, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return false, fmt.Errorf("%w: unable to acquire lock", ErrLedgerUnavailable)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	records, err := l.loadRecords()
	if err != nil {
		return false, err
	}
	active := make([]replayRecord, 0, len(records)+1)
	for _, record := range records {
		if record.RequestID == "" || record.ExpiresAt.IsZero() {
			return false, fmt.Errorf("%w: malformed persisted record", ErrLedgerUnavailable)
		}
		if record.ExpiresAt.After(now.UTC()) {
			if record.RequestID == requestID {
				return false, nil
			}
			active = append(active, record)
		}
	}
	if len(active) >= l.maxEntries {
		return false, fmt.Errorf("%w: capacity exhausted", ErrLedgerUnavailable)
	}
	active = append(active, replayRecord{RequestID: requestID, ExpiresAt: expiresAt.UTC()})
	sort.Slice(active, func(i, j int) bool { return active[i].RequestID < active[j].RequestID })
	if err := l.storeRecords(active); err != nil {
		return false, err
	}
	return true, nil
}

func (l *FileReplayLedger) loadRecords() ([]replayRecord, error) {
	info, err := os.Lstat(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: cannot inspect ledger", ErrLedgerUnavailable)
	}
	if err := l.validateOwnedRegular(info); err != nil {
		return nil, err
	}
	if info.Size() > l.maxLedgerBytes {
		return nil, fmt.Errorf("%w: ledger exceeds configured bound", ErrLedgerUnavailable)
	}
	file, err := l.openOwnedFile(l.path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, l.maxLedgerBytes+1))
	var records []replayRecord
	if err := decoder.Decode(&records); err != nil {
		return nil, fmt.Errorf("%w: unreadable ledger", ErrLedgerUnavailable)
	}
	if len(records) > l.maxEntries {
		return nil, fmt.Errorf("%w: ledger entry bound exceeded", ErrLedgerUnavailable)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing ledger data", ErrLedgerUnavailable)
	}
	return records, nil
}

func (l *FileReplayLedger) storeRecords(records []replayRecord) error {
	dir := filepath.Dir(l.path)
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("%w: unavailable random source", ErrLedgerUnavailable)
	}
	tempPath := filepath.Join(dir, ".ledger-"+hex.EncodeToString(random)+".tmp")
	temp, err := l.openOwnedFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tempPath)
	encoder := json.NewEncoder(temp)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(records); err != nil {
		temp.Close()
		return fmt.Errorf("%w: write failure", ErrLedgerUnavailable)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("%w: data sync failure", ErrLedgerUnavailable)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("%w: close failure", ErrLedgerUnavailable)
	}
	if err := os.Rename(tempPath, l.path); err != nil {
		return fmt.Errorf("%w: atomic replace failure", ErrLedgerUnavailable)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("%w: directory sync failure", ErrLedgerUnavailable)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("%w: directory sync failure", ErrLedgerUnavailable)
	}
	return nil
}

func (l *FileReplayLedger) checkParent() error {
	info, err := os.Lstat(filepath.Dir(l.path))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: unsafe ledger parent", ErrLedgerUnavailable)
	}
	if err := l.validateOwnedDirectory(info); err != nil {
		return err
	}
	return nil
}

func (l *FileReplayLedger) openOwnedFile(name string, flags int, mode os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(mode))
	if err != nil {
		return nil, fmt.Errorf("%w: unsafe file access", ErrLedgerUnavailable)
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("%w: cannot inspect opened file", ErrLedgerUnavailable)
	}
	if err := l.validateOwnedRegular(info); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func (l *FileReplayLedger) validateOwnedDirectory(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != l.ownerUID || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: insecure ledger directory", ErrLedgerUnavailable)
	}
	return nil
}

func (l *FileReplayLedger) validateOwnedRegular(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != l.ownerUID || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: insecure ledger file", ErrLedgerUnavailable)
	}
	return nil
}
