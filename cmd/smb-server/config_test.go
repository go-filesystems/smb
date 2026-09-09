package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hclPath quotes a path the way an HCL string wants it. On Windows a path is
// full of backslashes, and "C:\Users\alice" is a string with three invalid
// escape sequences in it -- which is a real thing a person writing this
// configuration will meet, not only a thing tests meet.
func hclPath(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A directory of small files is ONE configuration: a user in one and a share
// in another belong to the same server.
func TestADirectoryOfFilesIsOneConfiguration(t *testing.T) {
	dir := t.TempDir()
	pw := write(t, dir, "alice.pw", "hunter2\n")
	write(t, dir, "10-server.hcl", `
listen = "0.0.0.0:4445"
name   = "ATTIC"

user "alice" {
  password_file = "`+hclPath(pw)+`"
}
`)
	write(t, dir, "20-shares.hcl", `
share "photos" {
  image     = "/srv/photos.img"
  read_only = true
}

share "attic" {
  image = "/srv/attic.img"
}

user "bob" {
  password = "inline"
}
`)
	// Something that is not .hcl is not configuration, whatever it says.
	write(t, dir, "notes.txt", "share \"ignored\" { image = \"/nope\" }")

	cfg, err := loadConfig([]string{dir})
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if cfg.Listen != "0.0.0.0:4445" || cfg.Name != "ATTIC" {
		t.Errorf("server settings = %q, %q", cfg.Listen, cfg.Name)
	}
	if len(cfg.Shares) != 2 || len(cfg.Users) != 2 {
		t.Fatalf("%d shares and %d users, want 2 and 2", len(cfg.Shares), len(cfg.Users))
	}
	if !cfg.Shares[0].ReadOnly || cfg.Shares[1].ReadOnly {
		t.Error("read_only did not land on the share that asked for it")
	}
	// A password from a file loses its trailing newline, which every editor
	// adds and no client sends.
	if got, err := cfg.Users[0].password(); err != nil || got != "hunter2" {
		t.Errorf("the password file gave %q, %v", got, err)
	}
	if got, err := cfg.Users[1].password(); err != nil || got != "inline" {
		t.Errorf("the inline password gave %q, %v", got, err)
	}
}

// What a configuration cannot mean is refused, with the reason.
func TestConfigurationsThatCannotWork(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"no shares", `user "a" { password = "x" }`, "no shares"},
		{"no users", `share "s" { image = "/i" }`, "no users"},
		{
			"two shares under one name, whatever the case",
			`user "a" { password = "x" }
			 share "Disk" { image = "/a" }
			 share "disk" { image = "/b" }`,
			"without case",
		},
		{
			"a share with no image",
			`user "a" { password = "x" }
			 share "s" { image = "" }`,
			"no image",
		},
		{
			"a user twice",
			`user "a" { password = "x" }
			 user "a" { password = "y" }
			 share "s" { image = "/i" }`,
			"defined twice",
		},
		{
			"a user with no way to authenticate",
			"user \"a\" {\n}\nshare \"s\" { image = \"/i\" }",
			"neither a password",
		},
		{
			"a user with two ways",
			"user \"a\" {\n  password = \"x\"\n  password_file = \"/p\"\n}\nshare \"s\" { image = \"/i\" }",
			"say which one",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, "c.hcl", tc.body)
			_, err := loadConfig([]string{filepath.Join(dir, "c.hcl")})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// A syntax error says WHERE, because that is the whole reason for using a
// configuration language with diagnostics rather than a bag of flags.
func TestASyntaxErrorNamesThePlace(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "broken.hcl", "share \"s\" {\n  image = \n}\n")
	_, err := loadConfig([]string{p})
	if err == nil {
		t.Fatal("a file that is not HCL was accepted")
	}
	if !strings.Contains(err.Error(), "broken.hcl") {
		t.Errorf("the error does not name the file: %v", err)
	}
	if !strings.Contains(err.Error(), "2") && !strings.Contains(err.Error(), "3") {
		t.Errorf("the error does not name the line: %v", err)
	}

	// A block this server does not know is an error too, rather than silence:
	// a misspelt "share" would otherwise serve nothing and say nothing.
	q := write(t, dir, "unknown.hcl", "shear \"s\" { image = \"/i\" }\n")
	if _, err := loadConfig([]string{q}); err == nil {
		t.Error("an unknown block was accepted")
	}

	if _, err := loadConfig([]string{filepath.Join(dir, "absent.hcl")}); err == nil {
		t.Error("a file that is not there was accepted")
	}
	if _, err := loadConfig(nil); err == nil {
		t.Error("no files at all was accepted")
	}
	if _, err := loadConfig([]string{t.TempDir()}); err == nil {
		t.Error("an empty directory was accepted")
	}
	if _, err := (userBlock{Name: "a", PasswordFile: filepath.Join(dir, "gone")}).password(); err == nil {
		t.Error("a password file that is not there was accepted")
	}
}

// The flags are the one-image case and they stay; files and flags describing
// the same thing is a question nobody wants at three in the morning.
func TestFlagsAndFilesDoNotMix(t *testing.T) {
	dir := t.TempDir()
	pw := write(t, dir, "pw", "secret")
	p := write(t, dir, "c.hcl", `user "a" { password = "x" }
	 share "s" { image = "/i" }`)

	if _, err := configure([]string{p}, "/img", "", "", "", "a:1", "N", false); err == nil {
		t.Error("-config and -image together were accepted")
	}
	cfg, err := configure([]string{p}, "", "", "", "", "127.0.0.1:1", "NAME", false)
	if err != nil {
		t.Fatal(err)
	}
	// The two flags that are about the SERVER rather than what it serves fill
	// in what the files left out.
	if cfg.Listen != "127.0.0.1:1" || cfg.Name != "NAME" {
		t.Errorf("the flags did not fill in: %q, %q", cfg.Listen, cfg.Name)
	}

	// The one-image case: no file, and a share named after the image.
	cfg, err = configure(nil, "/srv/disk.img", "", "alice", pw, "a:1", "N", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 1 || cfg.Shares[0].Name != "disk" || !cfg.Shares[0].ReadOnly {
		t.Errorf("the one-image case gave %+v", cfg.Shares)
	}
	if len(cfg.Users) != 1 || cfg.Users[0].PasswordFile != pw {
		t.Errorf("the one-image case gave users %+v", cfg.Users)
	}
	if _, err := configure(nil, "/img", "", "", "", "a:1", "N", false); err == nil {
		t.Error("an image with no user was accepted")
	}
}

func TestDefaultShareName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"disk.img", "disk"},
		{"/srv/photos.qcow2", "photos"},
		{`C:\images\attic.img`, "attic"},
		{"noextension", "noextension"},
		{"", "disk"},
		{"/", "disk"},
	} {
		if got := defaultShareName(tc.in); got != tc.want {
			t.Errorf("defaultShareName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
