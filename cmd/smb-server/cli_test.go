package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The command line, exercised as a person types it.
//
// Every case here is a thing somebody will actually do: ask for help, check a
// configuration before restarting, mistype a dash, or name a file that is not
// there. The command is built fresh each time because cobra keeps parsed flag
// values on the command.
func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestHelpSaysWhatItServes(t *testing.T) {
	out, err := execute(t, "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--image", "--config", "check", "serve", "password comes from a FILE"} {
		if !strings.Contains(out, want) {
			t.Errorf("the help does not mention %q", want)
		}
	}
	// The one thing that must never be in a help text is a flag for a
	// password. It is a file, and the help says why.
	if strings.Contains(out, "--password ") {
		t.Error("there is a --password flag")
	}
}

// A single dash is what this command took before cobra, so the error says so
// rather than naming a one-letter flag nobody typed.
func TestASingleDashIsExplained(t *testing.T) {
	out, err := execute(t, "-config", "/etc/smb.d")
	if err == nil {
		t.Fatal("-config was accepted")
	}
	if !strings.Contains(err.Error(), "--config, not -config") {
		t.Errorf("the error does not say what to type: %v", err)
	}
	// The same lesson from the other direction: a long name with no shorthand
	// cannot be misread as one, so pflag itself refuses it and the hint is
	// added to what it said.
	_, err = execute(t, "-read-only")
	if err == nil || !strings.Contains(err.Error(), "--read-only, not -read-only") {
		t.Errorf("-read-only gave %v", err)
	}
	// A real one-letter flag that does not exist is left as pflag put it:
	// there is nothing to explain.
	if _, err := execute(t, "-Z"); err == nil || strings.Contains(err.Error(), "two dashes") {
		t.Errorf("an unknown short flag was explained as a long one: %v", err)
	}
	_ = out
}

func TestNothingToServeIsSaidPlainly(t *testing.T) {
	_, err := execute(t)
	if err == nil || !strings.Contains(err.Error(), "either --config") {
		t.Errorf("running with no arguments gave %v", err)
	}
	// A subcommand that does not exist is a typo, and it is answered as one:
	// with the command that was probably meant, not with a lecture about
	// dashes.
	_, err = execute(t, "chekc")
	if err == nil {
		t.Fatal("an unknown subcommand was accepted")
	}
	if !strings.Contains(err.Error(), "Did you mean this?") || !strings.Contains(err.Error(), "check") {
		t.Errorf("a typo was not answered with the command meant: %v", err)
	}
	// A leftover that is a path is a stale command line, and gets the dashes.
	_, err = execute(t, "/etc/smb.d")
	if err == nil || !strings.Contains(err.Error(), "two dashes") {
		t.Errorf("a leftover path gave %v", err)
	}
	// A leftover that is neither gets both, because it could be either.
	_, err = execute(t, "alice")
	if err == nil || !strings.Contains(err.Error(), "If you meant a flag") {
		t.Errorf("a leftover word gave %v", err)
	}
}

func TestCheckReadsTheConfigurationAndTheImages(t *testing.T) {
	dir := t.TempDir()
	// A real FAT32 image would need a driver to make one; what check must get
	// right is that it OPENS the file and says what it found -- so one image
	// that is not a filesystem is exactly the interesting case.
	img := filepath.Join(dir, "photos.img")
	if err := os.WriteFile(img, bytes.Repeat([]byte{0}, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	pw := write(t, dir, "alice.pw", "hunter2\n")
	write(t, dir, "c.hcl", `
listen = "0.0.0.0:4445"

user "alice" {
  password_file = "`+hclPath(pw)+`"
}

user "bob" {
  password = "inline"
}

share "photos" {
  image   = "`+hclPath(img)+`"
  allow   = ["alice", "bob"]
  writers = ["alice"]
}
`)

	out, err := execute(t, "check", dir)
	// The image is not a filesystem any driver owns, so check must FAIL --
	// that is the whole point of opening them.
	if err == nil {
		t.Errorf("check passed an image no driver can open:\n%s", out)
	}
	for _, want := range []string{
		"listening on 0.0.0.0:4445",
		"photos",
		"cannot open",
		"alice and bob", // who may connect
		"alice",         // who may write
		pw,              // where the password comes from, never the password
	} {
		if !strings.Contains(out, want) {
			t.Errorf("check did not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hunter2") {
		t.Error("check printed a password")
	}

	// And with nothing to check.
	if _, err := execute(t, "check"); err == nil {
		t.Error("check with no arguments was accepted")
	}
	// A configuration that cannot be parsed is refused with the reason, from
	// the same command.
	bad := write(t, dir, "bad.hcl", `share "s" {`)
	if _, err := execute(t, "check", bad); err == nil {
		t.Error("check accepted a file that does not parse")
	}
}

// check also reads the flag form, so a person can check what they are about to
// serve with the same words they would serve it.
func TestCheckReadsTheFlagsToo(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")
	if err := os.WriteFile(img, bytes.Repeat([]byte{0}, 512), 0o644); err != nil {
		t.Fatal(err)
	}
	pw := write(t, dir, "pw", "secret")
	out, _ := execute(t, "check", "--image", img, "--user", "alice", "--password-file", pw)
	if !strings.Contains(out, "disk") || !strings.Contains(out, "anyone who authenticates") {
		t.Errorf("check did not describe the one-image case:\n%s", out)
	}
	if strings.Contains(out, "secret") {
		t.Error("check printed a password")
	}
}

func TestVersionIsThere(t *testing.T) {
	out, err := execute(t, "--version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "smb-server version") {
		t.Errorf("--version printed %q", out)
	}
}

func TestAListReadsAsASentence(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"alice"}, "alice"},
		{[]string{"alice", "bob"}, "alice and bob"},
		{[]string{"alice", "bob", "carol"}, "alice, bob and carol"},
	} {
		if got := join(tc.in); got != tc.want {
			t.Errorf("join(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
