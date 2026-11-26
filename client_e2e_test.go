package smb_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	fssmb "github.com/go-filesystems/smb"
	"github.com/go-filesystems/smb/client"
	"github.com/go-filesystems/smb/client/smbc"
)

// The client of this module against the server of this module, over a socket:
// the end-to-end tests of the smbc command. The independent judge of the
// protocol stays go-smb2 in the other tests; here the point is the tool.

func clientTree(t *testing.T) *memFS {
	t.Helper()
	m := newMemFS(true)
	for _, d := range []string{"/a", "/a/b", "/c"} {
		if err := m.MkDir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]int{"/top.txt": 10, "/a/one": 100, "/a/b/two": 1000, "/c/three": 5}
	for p, n := range files {
		if err := m.WriteFile(p, bytes.Repeat([]byte("x"), n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func credFile(t *testing.T, user, pass string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the credentials-file mode and owner check refuses off unix (documented)")
	}
	p := filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(p, []byte("username="+user+"\npassword="+pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// smbcRun runs the command line and returns stdout, stderr and the exit code.
func smbcRun(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := smbc.RootCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := cmd.ExecuteContext(ctx)
	code := 0
	if err != nil {
		code = smbc.ExitFailure
		var ee *smbc.ExitError
		if errors.As(err, &ee) {
			code = ee.Code
		}
	}
	return out.String(), errb.String(), code
}

func TestSmbcLsDfDuCheckEndToEnd(t *testing.T) {
	addr, srv := serve(t)
	if err := srv.Share("disk", clientTree(t), fssmb.WithCapacity(1<<30, 1<<29)); err != nil {
		t.Fatal(err)
	}
	cf := credFile(t, "alice", "hunter2")
	unc := "//" + addr + "/disk"

	out, _, code := smbcRun(t, "ls", "--credentials-file", cf, unc)
	if code != 0 || !strings.Contains(out, "a/") || !strings.Contains(out, "top.txt") {
		t.Fatalf("ls: code %d\n%s", code, out)
	}
	out, _, code = smbcRun(t, "ls", "--credentials-file", cf, unc+"/a/b")
	if code != 0 || !strings.Contains(out, "two") || strings.Contains(out, "top.txt") {
		t.Fatalf("ls subdir: code %d\n%s", code, out)
	}

	out, _, code = smbcRun(t, "df", "--credentials-file", cf, unc)
	if code != 0 || !strings.Contains(out, "1073741824") || !strings.Contains(out, "536870912") {
		t.Fatalf("df: code %d\n%s", code, out)
	}
	out, _, code = smbcRun(t, "df", "--human-readable", "--credentials-file", cf, unc)
	if code != 0 || !strings.Contains(out, "1.0G") || !strings.Contains(out, "512.0M") {
		t.Fatalf("df -H: code %d\n%s", code, out)
	}

	out, _, code = smbcRun(t, "du", "--summarize", "--credentials-file", cf, unc)
	if code != 0 || strings.TrimSpace(out) != "1115\t/" {
		t.Fatalf("du -s: code %d %q", code, out)
	}
	out, _, code = smbcRun(t, "du", "--credentials-file", cf, unc)
	for _, want := range []string{"1000\t/a/b", "1100\t/a", "5\t/c", "1115\t/"} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("du: missing %q in\n%s", want, out)
		}
	}
	if code != 0 {
		t.Fatalf("du code %d", code)
	}
	out, _, code = smbcRun(t, "du", "-s", "--credentials-file", cf, unc+"/a")
	if code != 0 || strings.TrimSpace(out) != "1100\t/a" {
		t.Fatalf("du -s /a: code %d %q", code, out)
	}

	out, _, code = smbcRun(t, "check", "--credentials-file", cf, unc)
	if code != 0 || !strings.Contains(out, "OK:") {
		t.Fatalf("check: code %d\n%s", code, out)
	}
}

// check leaves no probe file behind.
func TestSmbcCheckLeavesNothingBehind(t *testing.T) {
	addr, srv := serve(t)
	fsys := clientTree(t)
	if err := srv.Share("disk", fsys); err != nil {
		t.Fatal(err)
	}
	_, _, code := smbcRun(t, "check", "--credentials-file", credFile(t, "alice", "hunter2"), "//"+addr+"/disk")
	if code != 0 {
		t.Fatalf("check code %d", code)
	}
	ents, err := fsys.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".smbc-check") {
			t.Fatalf("probe file %q left behind", e.Name())
		}
	}
}

// Each failure class has its own exit code and names its step.
func TestSmbcCheckNamesTheFailingStep(t *testing.T) {
	addr, srv := serve(t)
	if err := srv.Share("disk", clientTree(t)); err != nil {
		t.Fatal(err)
	}
	if err := srv.Share("ro", clientTree(t), fssmb.ReadOnly()); err != nil {
		t.Fatal(err)
	}
	good := credFile(t, "alice", "hunter2")
	bad := credFile(t, "alice", "wrong")

	cases := []struct {
		name string
		args []string
		code int
		step string
	}{
		{"auth", []string{"--credentials-file", bad, "//" + addr + "/disk"}, smbc.ExitAuth, "auth"},
		{"tree", []string{"--credentials-file", good, "//" + addr + "/nosuchshare"}, smbc.ExitTree, "tree"},
		{"read", []string{"--credentials-file", good, "//" + addr + "/disk/nodir"}, smbc.ExitRead, "read"},
		{"write", []string{"--credentials-file", good, "//" + addr + "/ro"}, smbc.ExitWrite, "write-create"},
		{"connect", []string{"--credentials-file", good, "--connect-timeout", "2s", "//127.0.0.1:1/disk"}, smbc.ExitConnect, "connect"},
		{"usage", []string{"--credentials-file", good, "not-a-unc"}, smbc.ExitUsage, ""},
		{"nocreds", []string{"//" + addr + "/disk"}, smbc.ExitUsage, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _, code := smbcRun(t, append([]string{"check"}, c.args...)...)
			if code != c.code {
				t.Fatalf("exit %d, want %d\n%s", code, c.code, out)
			}
			if c.step != "" && !strings.Contains(out, "FAIL at "+c.step) {
				t.Fatalf("verdict does not name %q:\n%s", c.step, out)
			}
		})
	}
}

// A wrong password must not appear anywhere the tool prints.
func TestSmbcNeverPrintsThePassword(t *testing.T) {
	addr, srv := serve(t)
	if err := srv.Share("disk", clientTree(t)); err != nil {
		t.Fatal(err)
	}
	bad := credFile(t, "alice", "Sup3rSecretPw")
	out, errb, _ := smbcRun(t, "check", "--credentials-file", bad, "//"+addr+"/disk")
	if strings.Contains(out+errb, "Sup3rSecretPw") {
		t.Fatalf("password printed:\n%s%s", out, errb)
	}
}

// Credentials file and systemd credential: the mode and owner rules.
func TestSmbcCredentialSources(t *testing.T) {
	addr, srv := serve(t)
	if err := srv.Share("disk", clientTree(t)); err != nil {
		t.Fatal(err)
	}
	unc := "//" + addr + "/disk"
	cf := credFile(t, "alice", "hunter2")

	if err := os.Chmod(cf, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, errb, code := smbcRun(t, "ls", "--credentials-file", cf, unc); code != smbc.ExitUsage {
		t.Fatalf("a group-readable file: exit %d (%s)", code, errb)
	}
	if err := os.Chmod(cf, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, _, code := smbcRun(t, "ls", "--credentials-file", cf, unc); code != 0 {
		t.Fatalf("0400 file refused: exit %d", code)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "smb"), []byte("username=alice\npassword=hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if _, _, code := smbcRun(t, "ls", "--credential", "smb", unc); code != 0 {
		t.Fatalf("systemd credential: exit %d", code)
	}
	if _, _, code := smbcRun(t, "ls", "--credential", "../smb", unc); code != smbc.ExitUsage {
		t.Fatalf("a credential name with a separator: exit %d", code)
	}
	if _, _, code := smbcRun(t, "ls", "--credential", "smb", "--credentials-file", cf, unc); code != smbc.ExitUsage {
		t.Fatalf("both sources: exit %d", code)
	}
}

// The API: a walk stops at its bound instead of trusting the server.
func TestClientDuIsBounded(t *testing.T) {
	addr, srv := serve(t)
	if err := srv.Share("disk", clientTree(t)); err != nil {
		t.Fatal(err)
	}
	tg, err := client.ParseUNC("//" + addr + "/disk")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for name, lim := range map[string]client.Limits{
		"nodes": {MaxWalkNodes: 3},
		"depth": {MaxDepth: 1},
		"dir":   {MaxDirEntries: 2},
	} {
		s, err := client.Dial(ctx, tg, client.Options{Auth: client.NTLM{Credentials: client.Credentials{User: "alice", Password: "hunter2"}}, Limits: lim})
		if err != nil {
			t.Fatal(err)
		}
		sh, err := s.Mount(tg.Share)
		if err != nil {
			t.Fatal(err)
		}
		_, err = sh.Du(ctx, "", client.DuOptions{})
		want := client.ErrTooMany
		if name == "depth" {
			want = client.ErrTooDeep
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", name, err, want)
		}
		sh.Close()
		s.Close()
	}
}

// A share that requires encryption is served: the client encrypts when the
// server asks, and the tool works the same.
func TestSmbcEncryptedShare(t *testing.T) {
	addr, srv := serve(t)
	if err := srv.Share("sec", clientTree(t), fssmb.RequireEncryption()); err != nil {
		t.Fatal(err)
	}
	cf := credFile(t, "alice", "hunter2")
	out, errb, code := smbcRun(t, "check", "--credentials-file", cf, "//"+addr+"/sec")
	if code != 0 {
		t.Fatalf("check on an encrypted share: exit %d\n%s%s", code, out, errb)
	}
}

// Error paths of the API: each names a failure instead of returning zeros.
func TestClientErrorPaths(t *testing.T) {
	addr, srv := serve(t)
	if err := srv.Share("disk", clientTree(t)); err != nil {
		t.Fatal(err)
	}
	tg, err := client.ParseUNC("//" + addr + "/disk")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, err := client.Dial(ctx, tg, client.Options{Auth: client.NTLM{Credentials: client.Credentials{User: "alice", Password: "hunter2"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Mount("nosuchshare"); err == nil {
		t.Fatal("a missing share was mounted")
	}
	sh, err := s.Mount("disk")
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	if _, err := sh.ReadDir("nodir"); err == nil {
		t.Error("ReadDir of a missing directory")
	}
	if _, err := sh.Statfs("nodir"); err == nil {
		t.Error("Statfs of a missing path")
	}
	if _, err := sh.Du(ctx, "nodir", client.DuOptions{}); err == nil {
		t.Error("Du of a missing root")
	}
	var seen []client.DuEntry
	n, err := sh.Du(ctx, "a/one", client.DuOptions{Visit: func(e client.DuEntry) { seen = append(seen, e) }})
	if err != nil || n != 100 || len(seen) != 1 || seen[0].Bytes != 100 {
		t.Errorf("Du of a file: %d %v %v", n, err, seen)
	}
	n, err = sh.Du(ctx, "a", client.DuOptions{})
	if err != nil || n != 1100 {
		t.Errorf("Du of a: %d %v", n, err)
	}
	var errs int
	if _, err := sh.Du(ctx, "", client.DuOptions{OnError: func(string, error) { errs++ }}); err != nil || errs != 0 {
		t.Errorf("Du of the root: %v, %d errors", err, errs)
	}
	ctx2, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := sh.Du(ctx2, "", client.DuOptions{}); err == nil {
		t.Error("Du with a cancelled context")
	}
	ents, err := sh.ReadDir("")
	if err != nil || len(ents) != 3 {
		t.Errorf("ReadDir root: %d %v", len(ents), err)
	}
}

// check on a path that is a file fails at the read step.
func TestSmbcCheckOnAFile(t *testing.T) {
	addr, srv := serve(t)
	if err := srv.Share("disk", clientTree(t)); err != nil {
		t.Fatal(err)
	}
	out, _, code := smbcRun(t, "check", "--credentials-file", credFile(t, "alice", "hunter2"), "//"+addr+"/disk/top.txt")
	if code != smbc.ExitRead || !strings.Contains(out, "FAIL at read") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}
