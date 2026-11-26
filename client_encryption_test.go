package smb_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	smb2 "github.com/go-filesystems/go-smb2"
	fssmb "github.com/go-filesystems/smb"
	"github.com/go-filesystems/smb/client"
	"github.com/go-filesystems/smb/client/smbc"
)

// plainServer serves a share from a server that does not offer encryption at
// all, so a client that requires it has nothing to negotiate.
func plainServer(t *testing.T) string {
	t.Helper()
	srv := fssmb.New()
	srv.DisableEncryption = true
	srv.AddUser("alice", "hunter2")
	if err := srv.Share("disk", clientTree(t)); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// By default the client requires encryption: a server that offers none is
// refused, and the refusal names the cause.
func TestClientRefusesAServerThatCannotEncrypt(t *testing.T) {
	addr := plainServer(t)
	tg, err := client.ParseUNC("//" + addr + "/disk")
	if err != nil {
		t.Fatal(err)
	}
	auth := client.NTLM{Credentials: client.Credentials{User: "alice", Password: "hunter2"}}
	_, err = client.Dial(context.Background(), tg, client.Options{Auth: auth})
	if !errors.Is(err, smb2.ErrEncryptionRequired) {
		t.Fatalf("Dial against a server with no encryption: %v, want ErrEncryptionRequired", err)
	}
	var se *client.StepError
	if !errors.As(err, &se) || se.Step != client.StepConnect {
		t.Fatalf("refusal %v is not a StepConnect error", err)
	}
	// The opt-out works, and says it is not encrypted.
	s, err := client.Dial(context.Background(), tg, client.Options{Auth: auth, AllowUnencrypted: true})
	if err != nil {
		t.Fatalf("AllowUnencrypted: %v", err)
	}
	defer s.Close()
	if s.Encrypted() {
		t.Error("a session with a server that cannot encrypt reports Encrypted")
	}
}

// Against a server that offers encryption but does not ask for it, the default
// client encrypts anyway.
func TestClientEncryptsWhenTheServerDoesNotAsk(t *testing.T) {
	addr, srv := serve(t)
	if err := srv.Share("disk", clientTree(t)); err != nil {
		t.Fatal(err)
	}
	tg, err := client.ParseUNC("//" + addr + "/disk")
	if err != nil {
		t.Fatal(err)
	}
	s, err := client.Dial(context.Background(), tg, client.Options{Auth: client.NTLM{Credentials: client.Credentials{User: "alice", Password: "hunter2"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.Encrypted() {
		t.Fatal("the session is not encrypted although encryption is required")
	}
	sh, err := s.Mount(tg.Share)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	if _, err := sh.ReadDir(""); err != nil {
		t.Fatalf("listing through the encrypted session: %v", err)
	}
}

// smbc refuses an unencrypted server unless --allow-unencrypted is given, and
// then it warns.
func TestSmbcRequiresEncryption(t *testing.T) {
	addr := plainServer(t)
	cf := credFile(t, "alice", "hunter2")
	unc := "//" + addr + "/disk"
	_, errb, code := smbcRun(t, "ls", "--credentials-file", cf, unc)
	if code != smbc.ExitConnect {
		t.Fatalf("ls against a server with no encryption: exit %d, want %d\n%s", code, smbc.ExitConnect, errb)
	}
	if strings.Contains(errb, "warning") {
		t.Errorf("a refusal printed the opt-out warning: %s", errb)
	}
	out, errb, code := smbcRun(t, "ls", "--credentials-file", cf, "--allow-unencrypted", unc)
	if code != 0 {
		t.Fatalf("ls --allow-unencrypted: exit %d\n%s%s", code, out, errb)
	}
	if !strings.Contains(errb, "--allow-unencrypted") || !strings.Contains(errb, "warning") {
		t.Errorf("no warning on stderr: %q", errb)
	}
}
