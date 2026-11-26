//go:build unix

package client

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeInfo struct{ sys any }

func (fakeInfo) Name() string       { return "f" }
func (fakeInfo) Size() int64        { return 0 }
func (fakeInfo) Mode() os.FileMode  { return 0o600 }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any         { return f.sys }

func TestCheckOwner(t *testing.T) {
	me := uint32(os.Geteuid())
	if err := checkOwner(fakeInfo{&syscall.Stat_t{Uid: me}}); err != nil {
		t.Fatal(err)
	}
	if err := checkOwner(fakeInfo{&syscall.Stat_t{Uid: me + 1}}); err == nil {
		t.Fatal("another owner accepted")
	}
	if err := checkOwner(fakeInfo{nil}); err == nil {
		t.Fatal("unreadable owner accepted")
	}
}

type fakeFile struct {
	info    os.FileInfo
	statErr error
	body    string
	readErr error
}

func (f fakeFile) Stat() (os.FileInfo, error) { return f.info, f.statErr }
func (f fakeFile) Read(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	return 0, io.EOF
}

type bodyFile struct {
	fakeFile
	r *strings.Reader
}

func (b bodyFile) Read(p []byte) (int, error) { return b.r.Read(p) }

func TestReadCredentialsFailures(t *testing.T) {
	me := uint32(os.Geteuid())
	mine := fakeInfo{&syscall.Stat_t{Uid: me}}
	good := bodyFile{fakeFile{info: mine}, strings.NewReader("username=u\npassword=p\n")}
	if c, err := readCredentials(good, "f"); err != nil || c.User != "u" {
		t.Fatalf("%v %v", c, err)
	}
	cases := map[string]openFile{
		"stat fails":    fakeFile{statErr: errors.New("boom")},
		"read fails":    fakeFile{info: mine, readErr: errors.New("boom")},
		"foreign owner": bodyFile{fakeFile{info: fakeInfo{&syscall.Stat_t{Uid: me + 1}}}, strings.NewReader("username=u\n")},
		"bad content":   bodyFile{fakeFile{info: mine}, strings.NewReader("bogus=1\n")},
	}
	for name, f := range cases {
		if _, err := readCredentials(f, "f"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadCredentialsFileNamesTheCause(t *testing.T) {
	_, err := LoadCredentialsFile(filepath.Join(t.TempDir(), "absent"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%v", err)
	}
	p := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(p, []byte("bogus=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentialsFile(p); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("%v", err)
	}
}
