package integrity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/brick/host-isolation/lifecycle"
	"github.com/brick/host-isolation/resource"
)

type resourceVerifier struct{ fail bool }

func (r resourceVerifier) VerifyPlan(resource.Plan) error {
	if r.fail {
		return errors.New("invalid resource")
	}
	return nil
}

type audit struct {
	fail   bool
	events int
}

func (a *audit) RecordEvent(string, string, string, string, map[string]any) error {
	a.events++
	if a.fail {
		return errors.New("audit unavailable")
	}
	return nil
}

type inspector struct {
	values map[string]FileIdentity
	fail   bool
}

func (i inspector) Inspect(path string) (FileIdentity, error) {
	if i.fail {
		return FileIdentity{}, errors.New("inspection unavailable")
	}
	value, ok := i.values[path]
	if !ok {
		return FileIdentity{}, errors.New("not found")
	}
	return value, nil
}

type fixture struct {
	key       ed25519.PrivateKey
	manifest  Manifest
	audit     *audit
	files     inspector
	authority *Authority
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	manifest := Manifest{
		Schema:     Schema,
		ManifestID: "manifest-shared-v1",
		Profile:    lifecycle.ProfileSharedTenant,
		Entries: []Entry{{
			Path:      "/runtime/bin/httpd",
			Digest:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			OwnerUID:  0,
			Mode:      0o755,
			Arguments: []string{"--foreground", "--port=8080"},
			Environment: []Environment{
				{Name: "HOME", Value: "/nonexistent"},
				{Name: "LANG", Value: "C.UTF-8"},
				{Name: "TMPDIR", Value: "/tmp"},
				{Name: "TZ", Value: "UTC"},
			},
			Interpreter:         &Dependency{Path: "/runtime/interpreters/loader", Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", OwnerUID: 0, Mode: 0o755},
			RuntimeDependencies: []Dependency{{Path: "/runtime/lib/libbrick.so", Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", OwnerUID: 0, Mode: 0o644}},
		}},
	}
	if err := SignManifest(&manifest, key); err != nil {
		t.Fatal(err)
	}
	files := inspector{values: map[string]FileIdentity{
		"/runtime/bin/httpd":           {Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", OwnerUID: 0, Mode: 0o755, Regular: true},
		"/runtime/interpreters/loader": {Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", OwnerUID: 0, Mode: 0o755, Regular: true},
		"/runtime/lib/libbrick.so":     {Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", OwnerUID: 0, Mode: 0o644, Regular: true},
	}}
	sink := &audit{}
	authority, err := NewAuthority(manifest, key.Public().(ed25519.PublicKey), resourceVerifier{}, files, sink)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{key: key, manifest: manifest, audit: sink, files: files, authority: authority}
}

func validPlan() resource.Plan {
	return resource.Plan{Schema: resource.Schema, CageID: "cage-tenant-a", Profile: lifecycle.ProfileSharedTenant, PlanDigest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
}

func validRequest() Request {
	return Request{Schema: Schema, CageID: "cage-tenant-a", Profile: lifecycle.ProfileSharedTenant, ResourcePlanDigest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", ExecutablePath: "/runtime/bin/httpd", Arguments: []string{"--foreground", "--port=8080"}}
}

func TestPrepareSignedManifestExecPlan(t *testing.T) {
	f := newFixture(t)
	plan, err := f.authority.Prepare(context.Background(), "spiffe://brick/adapter", validPlan(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.authority.VerifyPlan(plan); err != nil {
		t.Fatal(err)
	}
	if !plan.NoPathLookup || plan.CloseDescriptorsAt != 3 || len(plan.Environment) != 4 || f.audit.events != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestPrepareFailsClosedOnManifestRequestAndFileTampering(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fixture, *Request)
	}{
		{"requested_environment", func(_ *fixture, r *Request) {
			r.RequestedEnvironment = []Environment{{Name: "LD_PRELOAD", Value: "/tmp/payload"}}
		}},
		{"argument_injection", func(_ *fixture, r *Request) { r.Arguments = []string{"--foreground", ";id"} }},
		{"file_digest", func(f *fixture, _ *Request) {
			value := f.files.values["/runtime/bin/httpd"]
			value.Digest = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			f.files.values["/runtime/bin/httpd"] = value
			authority, err := NewAuthority(f.manifest, f.key.Public().(ed25519.PublicKey), resourceVerifier{}, f.files, f.audit)
			if err != nil {
				t.Fatal(err)
			}
			f.authority = authority
		}},
		{"dependency_symlink", func(f *fixture, _ *Request) {
			value := f.files.values["/runtime/lib/libbrick.so"]
			value.Symlink = true
			f.files.values["/runtime/lib/libbrick.so"] = value
			authority, err := NewAuthority(f.manifest, f.key.Public().(ed25519.PublicKey), resourceVerifier{}, f.files, f.audit)
			if err != nil {
				t.Fatal(err)
			}
			f.authority = authority
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, request := newFixture(t), validRequest()
			tc.mutate(&f, &request)
			if _, err := f.authority.Prepare(context.Background(), "actor", validPlan(), request); !errors.Is(err, ErrDenied) {
				t.Fatalf("error = %v, want denial", err)
			}
		})
	}
}

func TestAuthorityFailsClosedForSignatureAuditResourceAndCancellation(t *testing.T) {
	f := newFixture(t)
	f.manifest.Entries[0].Arguments = []string{"changed"}
	if _, err := NewAuthority(f.manifest, f.key.Public().(ed25519.PublicKey), resourceVerifier{}, f.files, f.audit); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("signature error = %v", err)
	}

	f = newFixture(t)
	f.audit.fail = true
	if _, err := f.authority.Prepare(context.Background(), "actor", validPlan(), validRequest()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("audit error = %v", err)
	}

	f = newFixture(t)
	authority, err := NewAuthority(f.manifest, f.key.Public().(ed25519.PublicKey), resourceVerifier{fail: true}, f.files, f.audit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Prepare(context.Background(), "actor", validPlan(), validRequest()); !errors.Is(err, ErrDenied) {
		t.Fatalf("resource error = %v", err)
	}

	f = newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.authority.Prepare(ctx, "actor", validPlan(), validRequest()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cancel error = %v", err)
	}
}
