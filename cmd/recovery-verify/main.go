package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/brick/host-isolation/lifecycle"
	"github.com/brick/host-isolation/recovery"
)

type clock struct{ now time.Time }

func (c clock) Now() time.Time { return c.now }

type journal struct{ events []recovery.Event }

func (j *journal) Append(event recovery.Event) error { j.events = append(j.events, event); return nil }

type audit struct{}

func (audit) RecordEvent(string, string, string, string, map[string]any) error { return nil }

type evidence struct{}

func (evidence) Capture(context.Context, string, string) (string, error) {
	return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
}

type controller struct{ calls []string }

func (c *controller) Kill(context.Context, string) error {
	c.calls = append(c.calls, "kill")
	return nil
}
func (c *controller) Freeze(context.Context, string) error {
	c.calls = append(c.calls, "freeze")
	return nil
}
func (c *controller) WithdrawNetwork(context.Context, string) error {
	c.calls = append(c.calls, "withdrawNetwork")
	return nil
}
func (c *controller) Destroy(context.Context, string) error {
	c.calls = append(c.calls, "destroy")
	return nil
}

type handoff struct{}

func (handoff) Handoff(context.Context, string, string) error { return nil }

func main() {
	if err := verify(); err != nil {
		fmt.Fprintf(os.Stderr, "host-isolation recovery verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("host-isolation recovery verification passed")
}
func verify() error {
	data, err := os.ReadFile("contracts/brick-host-isolation-recovery.v1.json")
	if err != nil {
		return err
	}
	var contract struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &contract); err != nil || contract.Schema != recovery.Schema {
		return fmt.Errorf("invalid recovery contract")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	journal := &journal{}
	controller := &controller{}
	authority, err := recovery.NewAuthority(key, journal, audit{}, evidence{}, controller, handoff{}, clock{time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		return err
	}
	request := recovery.Request{Schema: recovery.Schema, RecoveryID: "11111111-1111-4111-8111-111111111111", CageID: "cage-verify-a", CallerSPIFFEID: "spiffe://brick/verify", HostIdentity: "host-staging-a", PolicyDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ReasonCode: "anomaly"}
	attestation, err := authority.SuspendAndRecover(context.Background(), request)
	if err != nil {
		return err
	}
	if err := recovery.VerifyAttestation(attestation, key.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	if len(journal.events) != 7 || len(controller.calls) != 4 {
		return fmt.Errorf("incomplete recovery evidence")
	}
	for _, event := range journal.events {
		if err := recovery.VerifyEvent(event, key.Public().(ed25519.PublicKey)); err != nil {
			return err
		}
	}
	return nil
}

var _ lifecycle.AuditSink = audit{}
