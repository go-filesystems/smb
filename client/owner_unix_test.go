//go:build unix

package client

import (
	"os"
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
