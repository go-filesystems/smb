//go:build livemount

package smb_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	fssmb "github.com/go-filesystems/smb"
)

// `touch -d` on a mount is the Linux kernel client sending SET_INFO with
// FileBasicInformation (go-filesystems/smb#45). Before it, the server dropped
// the times and the next stat showed the old one.
func TestLiveTouchSetsTheTime(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mount -t cifs is Linux's")
	}
	if os.Geteuid() != 0 {
		if _, err := exec.LookPath("sudo"); err != nil {
			t.Skip("mounting needs root, and there is no sudo here")
		}
	}
	fsys := newSettableFS()
	if err := fsys.WriteFile("/touched.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := fssmb.New()
	srv.AddUser("alice", "hunter2")
	if err := srv.Share("disk", fsys); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	mnt := filepath.Join(t.TempDir(), "mnt")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	// actimeo=0: the kernel must ask the server rather than answer from a cache
	// of what it just sent.
	base := fmt.Sprintf("port=%d,username=alice,password=hunter2,uid=%d,gid=%d,actimeo=0",
		port, os.Getuid(), os.Getgid())
	out, err := run("mount", "-t", "cifs", "//127.0.0.1/disk", mnt, "-o", base)
	if err != nil {
		t.Logf("mounting without naming a dialect failed, trying 3.0: %v\n%s", err, out)
		if out, err = run("mount", "-t", "cifs", "//127.0.0.1/disk", mnt, "-o", base+",vers=3.0"); err != nil {
			fatal(t, "mounting with %q: %v\n%s", base, err, out)
		}
	}
	defer run("umount", mnt)

	file := filepath.Join(mnt, "touched.txt")
	cmd := exec.Command("touch", "-d", "2001-02-03 04:05:06", file)
	cmd.Env = append(os.Environ(), "TZ=UTC")
	if out, err := cmd.CombinedOutput(); err != nil {
		fatal(t, "touch -d: %v\n%s", err, out)
	}
	cmd = exec.Command("stat", "-c", "%Y", file)
	cmd.Env = append(os.Environ(), "TZ=UTC")
	got, err := cmd.Output()
	if err != nil {
		fatal(t, "stat: %v", err)
	}
	want := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC).Unix()
	if n, err := strconv.ParseInt(strings.TrimSpace(string(got)), 10, 64); err != nil || n != want {
		t.Errorf("stat shows mtime %q, touch set %d", got, want)
	}
	// And the filesystem underneath holds it, not just the client's cache.
	if m := fsys.mt["/touched.txt"]; m.Unix() != want {
		t.Errorf("the driver holds mtime %v, want unix %d", m, want)
	}
}
