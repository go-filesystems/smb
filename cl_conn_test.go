package smb_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	fssmb "github.com/go-filesystems/smb"
)

func clDial(t *testing.T, addr, user, pass string, allowPlain bool) (*fssmb.ClientConn, error) {
	t.Helper()
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c, err := fssmb.ClientDial(ctx, nc, fssmb.ClientOptions{User: user, Password: pass, Host: "127.0.0.1", AllowUnencrypted: allowPlain})
	if err == nil {
		t.Cleanup(func() { c.Close() })
	}
	return c, err
}

// The engine against this repository's own server: 3.1.1, NTLMv2, signed and
// ENCRYPTED, then the first increment's operations.
func TestTheOwnClientEngineReadsAShare(t *testing.T) {
	addr, srv := serve(t)
	fs := newMemFS(false)
	big := bytes.Repeat([]byte("0123456789abcdef"), 40000) // 640 KB: several credits
	if err := fs.WriteFile("/a.txt", []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/big.bin", big, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := srv.Share("disk", fs); err != nil {
		t.Fatal(err)
	}
	c, err := clDial(t, addr, "alice", "hunter2", false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Dialect() != 0x0311 || !c.Encrypted() {
		t.Fatalf("dialect %#x encrypted %v", c.Dialect(), c.Encrypted())
	}
	ctx := context.Background()
	sh, err := c.Mount(ctx, "disk")
	if err != nil {
		t.Fatal(err)
	}
	es, err := sh.ReadDir(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 2 {
		t.Fatalf("entries: %+v", es)
	}
	st, err := sh.Stat(ctx, "a.txt")
	if err != nil || st.Size != 5 || st.IsDir() {
		t.Fatalf("stat: %+v %v", st, err)
	}
	if _, err := sh.Stat(ctx, "nope"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	f, err := sh.Open(ctx, "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("read %d bytes: %v", len(got), err)
	}
	f.Close()
	if err := sh.WriteFile(ctx, "w.txt", []byte("written")); err != nil {
		t.Fatal(err)
	}
	if st, err := sh.Stat(ctx, "w.txt"); err != nil || st.Size != 7 {
		t.Fatalf("after write: %+v %v", st, err)
	}
	if err := sh.Remove(ctx, "w.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Stat(ctx, "w.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("after remove: %v", err)
	}
	if _, err := sh.Statfs(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Stat(ctx, "../x"); err == nil {
		t.Fatal("a .. path was sent")
	}
}

func TestTheOwnClientEngineRefusesAWrongPassword(t *testing.T) {
	addr, srv := serve(t)
	if err := srv.Share("disk", newMemFS(false)); err != nil {
		t.Fatal(err)
	}
	if _, err := clDial(t, addr, "alice", "wrong", false); err == nil {
		t.Fatal("a wrong password was accepted")
	}
}

// Encryption required, server that cannot encrypt: the dial fails, it does not
// fall back.
func TestTheOwnClientEngineRequiresEncryption(t *testing.T) {
	srv := fssmb.New()
	srv.AddUser("alice", "hunter2")
	srv.DisableEncryption = true
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	if err := srv.Share("disk", newMemFS(false)); err != nil {
		t.Fatal(err)
	}
	_, err = clDial(t, ln.Addr().String(), "alice", "hunter2", false)
	if !errors.Is(err, fssmb.ErrEncryptionRequired) {
		t.Fatalf("got %v", err)
	}
	c, err := clDial(t, ln.Addr().String(), "alice", "hunter2", true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Encrypted() {
		t.Fatal("encrypted without a cipher")
	}
	sh, err := c.Mount(context.Background(), "disk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sh.ReadDir(context.Background(), ""); err != nil {
		t.Fatalf("signed-only listing: %v", err)
	}
	_ = fmt.Sprint()
}
