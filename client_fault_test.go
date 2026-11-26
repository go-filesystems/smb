package smb_test

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-filesystems/smb/client/smbc"
)

// faultFS misbehaves on the probe file of check, to reach the steps a healthy
// server never fails: a read-back that differs, a read that errors, a delete
// that is refused.
type faultFS struct {
	*memFS
	mode   string
	stored atomic.Bool
}

func isProbe(p string) bool { return strings.Contains(p, ".smbc-check-") }

// WriteFile stores what a misbehaving disk would: altered or short data.
func (f *faultFS) WriteFile(p string, data []byte, m os.FileMode) error {
	if isProbe(p) {
		switch f.mode {
		case "tamper":
			if len(data) > 0 {
				data = append([]byte(nil), data...)
				data[len(data)-1] ^= 0xff
			}
		case "short":
			data = data[:len(data)/2]
		}
	}
	return f.memFS.WriteFile(p, data, m)
}

// ReadFile fails once the whole probe is stored: the reads that build it up
// chunk by chunk are the server's own.
func (f *faultFS) ReadFile(p string) ([]byte, error) {
	b, err := f.memFS.ReadFile(p)
	if f.mode == "readerr" && isProbe(p) && len(b) >= 4096 {
		return nil, errors.New("disk on fire")
	}
	return b, err
}

// DeleteFile does nothing, as the server ignores the error of a delete on close.
func (f *faultFS) DeleteFile(p string) error {
	if f.mode == "nodelete" && isProbe(p) {
		return nil
	}
	return f.memFS.DeleteFile(p)
}

func TestSmbcCheckNamesTheVerifyAndDeleteSteps(t *testing.T) {
	for mode, step := range map[string]string{
		"tamper":   "write-verify",
		"short":    "write-verify",
		"readerr":  "write-verify",
		"nodelete": "write-delete",
	} {
		t.Run(mode, func(t *testing.T) {
			addr, srv := serve(t)
			base := newMemFS(false)
			if err := srv.Share("disk", &faultFS{memFS: base, mode: mode}); err != nil {
				t.Fatal(err)
			}
			out, _, code := smbcRun(t, "check", "--credentials-file", credFile(t, "alice", "hunter2"), "//"+addr+"/disk")
			if code != smbc.ExitWrite || !strings.Contains(out, "FAIL at "+step) {
				t.Fatalf("exit %d:\n%s", code, out)
			}
			if mode != "nodelete" {
				ents, _ := base.ListDir("/")
				if len(ents) != 0 {
					t.Fatalf("a probe file was left behind after %s", mode)
				}
			}
		})
	}
}
