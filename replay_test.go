package smb_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"

	fssmb "github.com/go-filesystems/smb"
)

// The reviewer-style repro of the replay: a recording proxy sits between a real
// client (go-smb2) and the server, the client does its work, one request is
// captured as it went on the wire -- signed, or encrypted -- and the proxy sends
// those very bytes again on the server's connection. A signature and an
// authentication tag prove who made a message, not that it is new, so before the
// command sequence window the server carried the request out a second time and
// answered it. Now it ends the connection and answers nothing.

// recorder forwards a TCP connection and remembers the frames the client sent.
type recorder struct {
	up       net.Conn
	mu       sync.Mutex
	frames   [][]byte
	fromSrv  chan []byte // every frame the server sent
	srvClose chan struct{}
}

func frameOf(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]) & 0x00FFFFFF)
	b := make([]byte, 4+n)
	copy(b, hdr[:])
	_, err := io.ReadFull(r, b[4:])
	return b, err
}

func newRecorder(t *testing.T, upstream string) (addr string, rec *recorder) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	rec = &recorder{fromSrv: make(chan []byte, 1024), srvClose: make(chan struct{})}
	go func() {
		down, err := ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", upstream)
		if err != nil {
			return
		}
		rec.up = up
		t.Cleanup(func() { up.Close(); down.Close() })
		go func() { // client to server, recorded
			for {
				f, err := frameOf(down)
				if err != nil {
					return
				}
				rec.mu.Lock()
				rec.frames = append(rec.frames, f)
				rec.mu.Unlock()
				if _, err := up.Write(f); err != nil {
					return
				}
			}
		}()
		go func() { // server to client
			defer close(rec.srvClose)
			for {
				f, err := frameOf(up)
				if err != nil {
					return
				}
				rec.fromSrv <- f
				if _, err := down.Write(f); err != nil {
					return
				}
			}
		}()
	}()
	return ln.Addr().String(), rec
}

func (r *recorder) last() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.frames[len(r.frames)-1]
}

func TestAReplayedFrameIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name      string
		dialect   uint16
		encrypted bool
	}{
		{"signed, 3.1.1", 0x0311, false},
		{"signed, 3.0.2", 0x0302, false},
		{"encrypted, 3.1.1", 0x0311, true},
		{"encrypted, 3.0", 0x0300, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, srv := serve(t)
			mem := newMemFS(true)
			mem.WriteFile("/a.txt", []byte("0123456789"), 0o644)
			var opts []fssmb.ShareOption
			if tc.encrypted {
				opts = append(opts, fssmb.RequireEncryption())
			}
			if err := srv.Share("disk", mem, opts...); err != nil {
				t.Fatal(err)
			}
			proxy, rec := newRecorder(t, addr)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			d := &smb2.Dialer{
				Negotiator: smb2.Negotiator{SpecifiedDialect: tc.dialect, RequireMessageSigning: !tc.encrypted},
				Initiator:  &smb2.NTLMInitiator{User: "alice", Password: "hunter2"},
			}
			s, err := d.Dial(ctx, proxy)
			if err != nil {
				t.Fatalf("dialing: %v", err)
			}
			fs, err := s.Mount("disk")
			if err != nil {
				t.Fatal(err)
			}
			// The server ends the connection at the end of this test, and a
			// goroutine waiting for a reply on it would wait forever: the cleanup
			// carries its own, short, deadline.
			defer func() {
				short, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer stop()
				fs.WithContext(short).Umount()
				s.WithContext(short).Logoff()
			}()
			if got, err := fs.ReadFile("a.txt"); err != nil || string(got) != "0123456789" {
				t.Fatalf("reading: %q %v", got, err)
			}
			// Let the client's last reply arrive, then capture the last request as it
			// went on the wire.
			time.Sleep(200 * time.Millisecond)
			captured := rec.last()
			wantEnc := tc.encrypted
			if isEnc := captured[4] == 0xFD; isEnc != wantEnc {
				t.Fatalf("the captured frame is encrypted=%v, want %v", isEnc, wantEnc)
			}
			for len(rec.fromSrv) > 0 {
				<-rec.fromSrv
			}

			// The replay: the same bytes, on the server's connection, behind the
			// client's back.
			if _, err := rec.up.Write(captured); err != nil {
				t.Fatalf("replaying: %v", err)
			}
			select {
			case f := <-rec.fromSrv:
				t.Fatalf("the server answered a replayed frame (%d bytes)", len(f))
			case <-rec.srvClose:
				// the connection was ended
			case <-time.After(3 * time.Second):
				t.Fatal("the server neither answered nor ended the connection")
			}
		})
	}
}
