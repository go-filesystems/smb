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
