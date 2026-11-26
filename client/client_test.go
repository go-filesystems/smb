package client

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseUNC(t *testing.T) {
	good := map[string]Target{
		"//h/s":                 {"h", "445", "s", ""},
		"//h/s/":                {"h", "445", "s", ""},
		"//h/s/a/b":             {"h", "445", "s", "a/b"},
		`\\h\s\a\b`:             {"h", "445", "s", "a/b"},
		"//h:4450/s/a//b/./c":   {"h", "4450", "s", "a/b/c"},
		"//[::1]:445/s":         {"::1", "445", "s", ""},
		"//[fe80::1]/s/x":       {"fe80::1", "445", "s", "x"},
		"//192.0.2.1/data/x y/": {"192.0.2.1", "445", "data", "x y"},
	}
	for in, want := range good {
		got, err := ParseUNC(in)
		if err != nil || got != want {
			t.Errorf("ParseUNC(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "h/s", "/h/s", "//", "//h", "//h/", "///s", "//h/s/../x", "//h/s/a/..", "//h/..",
		"//h/s/a\x00b", "//h/s/a\nb", "//:445/s", "//h:/s", "//a:b:c/s", "//[::1/s", "//h]/s",
		"//h/s/" + strings.Repeat("a/", maxPathDeep+1), "//h/" + strings.Repeat("s", maxNameLen),
	} {
		if got, err := ParseUNC(in); err == nil {
			t.Errorf("ParseUNC(%q) = %+v, want an error", in, got)
		}
	}
}

func TestParseCredentials(t *testing.T) {
	c, err := ParseCredentials([]byte("# a comment\r\nusername = alice \r\npassword=pa ss=word \n; x\ndomain=CORP\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.User != "alice" || c.Password != "pa ss=word " || c.Domain != "CORP" {
		t.Fatalf("%#v", c)
	}
	c, err = ParseCredentials([]byte("user=bob\npass=x\nworkgroup=W\n"))
	if err != nil || c.User != "bob" || c.Password != "x" || c.Domain != "W" {
		t.Fatalf("%#v %v", c, err)
	}
	for _, in := range []string{
		"", "password=x\n", "username=a\nusername=b\n", "username=a\nfoo=1\n", "username=a\njunk\n",
		"username=a\npassword=" + strings.Repeat("x", maxCredentialsFile) + "\n",
	} {
		if _, err := ParseCredentials([]byte(in)); err == nil {
			t.Errorf("ParseCredentials(%.40q) accepted", in)
		}
	}
}

// An error about a credentials line never carries the secret.
func TestCredentialErrorsDoNotEchoTheValue(t *testing.T) {
	_, err := ParseCredentials([]byte("username=a\nusername=SECRETVALUE\n"))
	if err == nil || strings.Contains(err.Error(), "SECRETVALUE") {
		t.Fatalf("%v", err)
	}
	_, err = ParseCredentials([]byte("username=a\nSECRETKEYVALUE=SECRETVALUE\n"))
	if err == nil || strings.Contains(err.Error(), "SECRETVALUE") {
		t.Fatalf("%v", err)
	}
}

func TestCredentialsNeverPrintThePassword(t *testing.T) {
	c := Credentials{User: "alice", Password: "SECRETVALUE"}
	for _, s := range []string{c.String(), strings.TrimSpace(sprintAll(c))} {
		if strings.Contains(s, "SECRETVALUE") {
			t.Fatalf("leaked: %s", s)
		}
	}
}

func sprintAll(c Credentials) string {
	return fmt.Sprintf("%v %+v %#v %v %s", c, c, c, &c, c)
}

func TestLoadCredentialsFileRefusals(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c")
	write := func(mode os.FileMode) {
		t.Helper()
		os.Remove(p)
		if err := os.WriteFile(p, []byte("username=a\npassword=b\n"), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
	}
	for _, m := range []os.FileMode{0o600, 0o400} {
		write(m)
		if _, err := LoadCredentialsFile(p); err != nil {
			t.Errorf("mode %o refused: %v", m, err)
		}
	}
	for _, m := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666, 0o601} {
		write(m)
		if _, err := LoadCredentialsFile(p); err == nil {
			t.Errorf("mode %o accepted", m)
		}
	}
	if _, err := LoadCredentialsFile(dir); err == nil {
		t.Error("a directory accepted")
	}
	if _, err := LoadCredentialsFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file accepted")
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte("username=a\n#"+strings.Repeat("x", maxCredentialsFile)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentialsFile(big); err == nil {
		t.Error("an oversized file accepted")
	}
}

func TestSystemdCredentialName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "smb"), []byte("username=a\npassword=b\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if c, err := loadSystemdCredential("smb", dir); err != nil || c.User != "a" {
		t.Fatalf("%v %v", c, err)
	}
	for _, n := range []string{"", ".", "..", "../smb", "a/b", `a\b`, "smb\x00"} {
		if _, err := loadSystemdCredential(n, dir); err == nil {
			t.Errorf("name %q accepted", n)
		}
	}
	if _, err := loadSystemdCredential("smb", ""); err == nil {
		t.Error("no CREDENTIALS_DIRECTORY accepted")
	}
}

func TestFsInfoOf(t *testing.T) {
	fi, err := fsInfoOf(4096, 100, 50, 25)
	if err != nil || fi != (FSInfo{409600, 204800, 102400}) {
		t.Fatalf("%+v %v", fi, err)
	}
	for _, c := range [][4]uint64{
		{0, 1, 1, 1},                 // a zero unit
		{1 << 31, 1, 1, 1},           // a unit above 1 GiB
		{4096, math.MaxUint64, 1, 1}, // a negative count on the wire (signed field)
		{4096, 1, 1 << 63, 1},
		{1 << 30, math.MaxInt64 / 2, 1, 1}, // the product overflows
	} {
		if _, err := fsInfoOf(c[0], c[1], c[2], c[3]); !errors.Is(err, ErrBadFSInfo) {
			t.Errorf("%v: %v", c, err)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"", ".", "..", "a/b", `a\b`, "a\x00"} {
		if validName(n) {
			t.Errorf("%q valid", n)
		}
	}
	for _, n := range []string{"a", "..a", "a b", "é"} {
		if !validName(n) {
			t.Errorf("%q invalid", n)
		}
	}
}
