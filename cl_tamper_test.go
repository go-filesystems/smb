package smb_test

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	fssmb "github.com/go-filesystems/smb"
)

// tamperProxy relays one connection and flips the last bit of the last byte of
// every server-to-client frame from the (first+1)th on, once armed.
func tamperProxy(t *testing.T, upstream string, armed *atomic.Bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		cc, err := ln.Accept()
		if err != nil {
			return
		}
		sc, err := net.Dial("tcp", upstream)
		if err != nil {
			cc.Close()
			return
		}
		go io.Copy(sc, cc)
		for {
			var hdr [4]byte
			if _, err := io.ReadFull(sc, hdr[:]); err != nil {
				cc.Close()
				return
			}
			n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
			body := make([]byte, n)
			if _, err := io.ReadFull(sc, body); err != nil {
				cc.Close()
				return
			}
			if armed.Load() {
				body[len(body)-1] ^= 1
			}
			cc.Write(append(hdr[:], body...))
		}
	}()
	return ln.Addr().String()
}

// A bit flipped in a response after the session is up -- in the ciphertext when
// encrypted, in the signed message otherwise -- ends the connection with an
// error, never with data.
func TestTheOwnClientEngineRefusesATamperedResponse(t *testing.T) {
	for _, plain := range []bool{false, true} {
		srv := fssmb.New()
		srv.AddUser("alice", "hunter2")
		srv.DisableEncryption = plain
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		fs := newMemFS(false)
		fs.WriteFile("/a.txt", []byte("hello"), 0o644)
		if err := srv.Share("disk", fs); err != nil {
			t.Fatal(err)
		}
		var armed atomic.Bool
		c, err := clDial(t, tamperProxy(t, ln.Addr().String(), &armed), "alice", "hunter2", plain)
		if err != nil {
			t.Fatal(err)
		}
		sh, err := c.Mount(context.Background(), "disk")
		if err != nil {
			t.Fatal(err)
		}
		armed.Store(true)
		// the refusal must come from the connection ending, not from a caller
		// giving up on a reader that went on waiting
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if st, err := sh.Stat(ctx, "a.txt"); err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("plain=%v: a tampered response: %+v, %v", plain, st, err)
		}
		if _, err := sh.Stat(ctx, "a.txt"); err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("plain=%v: the connection survived a tampered response: %v", plain, err)
		}
		cancel()
	}
}
