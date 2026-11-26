package client

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type failAuth struct{}

func (failAuth) Initiator(string) (Initiator, error) { return nil, errors.New("no initiator") }

func TestNTLMNeedsAUser(t *testing.T) {
	if _, err := (NTLM{}).Initiator("h"); err == nil {
		t.Fatal("an empty user name was accepted")
	}
	if _, err := (NTLM{Credentials{User: "u"}}).Initiator("h"); err != nil {
		t.Fatal(err)
	}
}

func TestDialStepsOfFailure(t *testing.T) {
	tg := Target{Host: "h", Port: "1", Share: "s"}
	cases := []struct {
		name string
		o    Options
		step Step
	}{
		{"no authenticator", Options{}, StepAuth},
		{"authenticator fails", Options{Auth: failAuth{}}, StepAuth},
		{"dial fails", Options{Auth: NTLM{Credentials{User: "u"}}, DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("refused")
		}}, StepConnect},
	}
	for _, c := range cases {
		_, err := Dial(context.Background(), tg, c.o)
		var se *StepError
		if !errors.As(err, &se) || se.Step != c.step {
			t.Errorf("%s: got %v, want step %s", c.name, err, c.step)
		}
	}
}

func TestParseUNCEmptyHost(t *testing.T) {
	for _, s := range []string{"//:445/share", "//[]/share", "//host:/share"} {
		if _, err := ParseUNC(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestCredentialsFileNotRegular(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadCredentialsFile(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a directory: %v", err)
	}
	if _, err := LoadCredentialsFile(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("a missing file was read")
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte("username=u\npassword="+strings.Repeat("x", maxCredentialsFile)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentialsFile(big); err == nil {
		t.Fatal("an oversized file was read")
	}
	ok := filepath.Join(dir, "ok")
	if err := os.WriteFile(ok, []byte("username=u\npassword=p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCredentialsFile(ok)
	if err != nil || c.User != "u" || c.Password != "p" {
		t.Fatalf("%v %v", c, err)
	}
}

func TestSystemdCredentialRefusals(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"", ".", "..", "a/b", `a\b`, "a\x00b"} {
		if _, err := loadSystemdCredential(n, dir); err == nil || !strings.Contains(err.Error(), "plain file name") {
			t.Errorf("%q: %v", n, err)
		}
	}
	if _, err := loadSystemdCredential("x", ""); err == nil || !strings.Contains(err.Error(), "CREDENTIALS_DIRECTORY") {
		t.Errorf("no directory: %v", err)
	}
}

func TestParseCredentialsNeedsEquals(t *testing.T) {
	if _, err := ParseCredentials([]byte("username=u\nnonsense\n")); err == nil || !strings.Contains(err.Error(), "key=value") {
		t.Fatalf("%v", err)
	}
	if _, err := ParseCredentials([]byte("password=p\n")); err == nil {
		t.Fatal("no username accepted")
	}
}

func TestAddSatSaturates(t *testing.T) {
	if got := addSat(math.MaxInt64-1, 5); got != math.MaxInt64 {
		t.Fatalf("got %d", got)
	}
	if got := addSat(math.MaxInt64, 1); got != math.MaxInt64 {
		t.Fatalf("got %d", got)
	}
	if got := addSat(math.MaxInt64-5, 5); got != math.MaxInt64 {
		t.Fatalf("got %d", got)
	}
	if got := addSat(3, 4); got != 7 {
		t.Fatalf("got %d", got)
	}
	if got := addSat(3, -4); got != -1 {
		t.Fatalf("got %d", got)
	}
}

type batchDir struct {
	batches [][]os.FileInfo
	err     error
	calls   int
}

func (b *batchDir) Readdir(int) ([]os.FileInfo, error) {
	b.calls++
	if b.calls > 100 {
		return nil, io.EOF // the test's own bound: a loop would be reported below
	}
	if len(b.batches) == 0 {
		return nil, b.err
	}
	x := b.batches[0]
	b.batches = b.batches[1:]
	return x, nil
}

type nameInfo struct {
	fakeName string
}

func (n nameInfo) Name() string     { return n.fakeName }
func (nameInfo) Size() int64        { return -5 }
func (nameInfo) Mode() os.FileMode  { return 0 }
func (nameInfo) ModTime() time.Time { return time.Time{} }
func (nameInfo) IsDir() bool        { return false }
func (nameInfo) Sys() any           { return nil }

func TestReadEntries(t *testing.T) {
	// An empty batch with no error ends the listing.
	d := &batchDir{}
	if ents, err := readEntries(d, "p", 10); err != nil || len(ents) != 0 || d.calls != 1 {
		t.Fatalf("empty batch: %v %v calls=%d", ents, err, d.calls)
	}
	// io.EOF after entries ends it too, keeping the entries; a size below zero reads as 0.
	d = &batchDir{batches: [][]os.FileInfo{{nameInfo{"a"}, nameInfo{"../x"}, nameInfo{"b"}}}, err: io.EOF}
	ents, err := readEntries(d, "p", 10)
	if err != nil || len(ents) != 2 || ents[0].Size != 0 {
		t.Fatalf("%v %v", ents, err)
	}
	// Another error is returned with what was read.
	d = &batchDir{batches: [][]os.FileInfo{{nameInfo{"a"}}}, err: errors.New("boom")}
	if ents, err := readEntries(d, "p", 10); err == nil || len(ents) != 1 {
		t.Fatalf("%v %v", ents, err)
	}
	// The bound is on kept entries.
	d = &batchDir{batches: [][]os.FileInfo{{nameInfo{"a"}, nameInfo{"b"}, nameInfo{"c"}}}, err: io.EOF}
	if _, err := readEntries(d, "p", 2); !errors.Is(err, ErrTooMany) {
		t.Fatalf("%v", err)
	}
	d = &batchDir{batches: [][]os.FileInfo{{nameInfo{"a"}, nameInfo{"b"}}}, err: io.EOF}
	if ents, err := readEntries(d, "p", 2); err != nil || len(ents) != 2 {
		t.Fatalf("at the bound: %v %v", ents, err)
	}
}
