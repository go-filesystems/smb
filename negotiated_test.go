package smb_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"

	fssmb "github.com/go-filesystems/smb"
)

// lockedBuffer is a log sink the server's goroutines and the test may both use.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Encryption, with a client this project did not write: go-smb2 offers every
// cipher it has (AES-128-CCM and AES-128-GCM, and the 256-bit ones), encrypts
// what the server's TREE_CONNECT or SESSION_SETUP says to, and decrypts and
// authenticates what the server sends -- so a share that is read and written
// through it proves both directions and both derived keys against an independent
// implementation of the same specification.
func TestEncryptedSessions(t *testing.T) {
	body := bytes.Repeat([]byte("encrypted through the share "), 20000) // 560 kB: multi-credit, several frames
	for _, tc := range []struct {
		name    string
		dialect uint16
		global  bool // Server.EncryptData; otherwise RequireEncryption on the share
		cipher  string
	}{
		{"3.0, share", 0x0300, false, "AES-128-CCM"},
		{"3.0.2, share", 0x0302, false, "AES-128-CCM"},
		{"3.1.1, share", 0x0311, false, "AES-128-"},
		{"3.0.2, whole server", 0x0302, true, "AES-128-CCM"},
		{"3.1.1, whole server", 0x0311, true, "AES-128-"},
		{"everything it offers, share", 0, false, "AES-128-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, srv := serve(t)
			var log lockedBuffer
			srv.Logger = slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))
			srv.EncryptData = tc.global
			mem := newMemFS(true)
			var opts []fssmb.ShareOption
			if !tc.global {
				opts = append(opts, fssmb.RequireEncryption())
			}
			if err := srv.Share("disk", mem, opts...); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			d := &smb2.Dialer{
				Negotiator: smb2.Negotiator{SpecifiedDialect: tc.dialect},
				Initiator:  &smb2.NTLMInitiator{User: "alice", Password: "hunter2"},
			}
			s, err := d.Dial(ctx, addr)
			if err != nil {
				t.Fatalf("dialing: %v", err)
			}
			defer s.Logoff()
			fs, err := s.Mount("disk")
			if err != nil {
				t.Fatalf("connecting to the share: %v", err)
			}
			defer fs.Umount()
			if err := fs.WriteFile("through.txt", body, 0o644); err != nil {
				t.Fatalf("writing: %v", err)
			}
			got, err := fs.ReadFile("through.txt")
			if err != nil || !bytes.Equal(got, body) {
				t.Fatalf("reading back: %d bytes, %v", len(got), err)
			}
			if ents, err := fs.ReadDir("."); err != nil || len(ents) != 1 {
				t.Errorf("listing: %v %v", ents, err)
			}
			logged := log.String()
			if !strings.Contains(logged, "smb first encrypted request") || !strings.Contains(logged, "cipher="+tc.cipher) {
				t.Errorf("the server did not log an encrypted request with %s:\n%s", tc.cipher, logged)
			}
			if strings.Contains(logged, "dialect=3.1.1") && !strings.Contains(logged, "cipher=AES-128-") {
				t.Errorf("a 3.1.1 session with no cipher:\n%s", logged)
			}
		})
	}

	// A client that cannot encrypt is refused where the rule applies, and the
	// refusal is the one MS-SMB2 names: ACCESS_DENIED.
	t.Run("2.1 cannot use it", func(t *testing.T) {
		for _, global := range []bool{false, true} {
			addr, srv := serve(t)
			srv.EncryptData = global
			var opts []fssmb.ShareOption
			if !global {
				opts = append(opts, fssmb.RequireEncryption())
			}
			if err := srv.Share("disk", newMemFS(true), opts...); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			d := &smb2.Dialer{
				Negotiator: smb2.Negotiator{SpecifiedDialect: 0x0210},
				Initiator:  &smb2.NTLMInitiator{User: "alice", Password: "hunter2"},
			}
			s, err := d.Dial(ctx, addr)
			if err == nil {
				// Not refused at SESSION_SETUP, so it must be at TREE_CONNECT.
				if fs, merr := s.Mount("disk"); merr == nil {
					fs.Umount()
					t.Errorf("global=%v: a 2.1 client reached an encrypted share", global)
				}
				s.Logoff()
			} else if !global {
				t.Errorf("a 2.1 client was refused a session by a per-share rule: %v", err)
			}
			cancel()
		}
	})
}

// The flag comes from the client's NEGOTIATE: a client that requires signing
// gets a session that does (and signs everything, so every request is carried
// out), one that does not, does not. Read from the server's side, with go-smb2 as
// the client, across the dialects that sign with each algorithm.
func TestSigningRequiredComesFromTheClient(t *testing.T) {
	for _, dialect := range []uint16{0x0210, 0x0300, 0x0302, 0x0311} {
		for _, required := range []bool{true, false} {
			addr, srv := serve(t)
			var log lockedBuffer
			srv.Logger = slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))
			mem := newMemFS(true)
			mem.WriteFile("/a.txt", []byte("signed"), 0o644)
			if err := srv.Share("disk", mem); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			d := &smb2.Dialer{
				Negotiator: smb2.Negotiator{SpecifiedDialect: dialect, RequireMessageSigning: required},
				Initiator:  &smb2.NTLMInitiator{User: "alice", Password: "hunter2"},
			}
			s, err := d.Dial(ctx, addr)
			if err != nil {
				t.Fatalf("%#04x required=%v: %v", dialect, required, err)
			}
			fs, err := s.Mount("disk")
			if err != nil {
				t.Fatalf("%#04x required=%v: %v", dialect, required, err)
			}
			if got, err := fs.ReadFile("a.txt"); err != nil || string(got) != "signed" {
				t.Errorf("%#04x required=%v: reading: %q %v", dialect, required, got, err)
			}
			fs.Umount()
			s.Logoff()
			cancel()
			want := "signing_required=false"
			if required {
				want = "signing_required=true"
			}
			if !strings.Contains(log.String(), want) {
				t.Errorf("%#04x required=%v: the server logged %q", dialect, required, log.String())
			}
		}
	}
}

// What a client NEGOTIATED, read from the server's side: a session logs its
// dialect and signing algorithm at Debug level. go-smb2 is a client this
// project did not write, and it checks the server's signature on the session
// setup that ends the exchange, so a 3.1.1 session that logs is one whose
// pre-authentication hash and signing key both agreed with an independent
// implementation.
func TestWhatAClientNegotiated(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dialect uint16 // as go-smb2 spells it; 0 offers everything it speaks
		want    string
	}{
		{"offers everything", 0, "dialect=3.1.1 signing=AES-128-CMAC"},
		{"3.1.1", 0x0311, "dialect=3.1.1 signing=AES-128-CMAC"},
		{"3.0.2", 0x0302, "dialect=3.0.2 signing=AES-128-CMAC"},
		{"3.0", 0x0300, "dialect=3.0 signing=AES-128-CMAC"},
		{"2.1", 0x0210, "dialect=2.1 signing=HMAC-SHA256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, srv := serve(t)
			var log lockedBuffer
			srv.Logger = slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))
			if err := srv.Share("disk", stubFS{}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			d := &smb2.Dialer{
				Negotiator: smb2.Negotiator{SpecifiedDialect: tc.dialect, RequireMessageSigning: true},
				Initiator:  &smb2.NTLMInitiator{User: "alice", Password: "hunter2"},
			}
			s, err := d.Dial(ctx, addr)
			if err != nil {
				t.Fatalf("dialing: %v", err)
			}
			defer s.Logoff()
			// A signed exchange after the handshake: the keys must agree for the
			// share to be reachable at all.
			fs, err := s.Mount("disk")
			if err != nil {
				t.Fatalf("connecting to the share: %v", err)
			}
			defer fs.Umount()
			if got := log.String(); !strings.Contains(got, tc.want) {
				t.Errorf("the server logged %q, want it to contain %q", got, tc.want)
			}
		})
	}
}
