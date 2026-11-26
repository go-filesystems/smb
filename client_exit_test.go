package smb_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-filesystems/smb/client/smbc"

	filesystem "github.com/go-filesystems/interface"
)

// Every subcommand maps each failure to its own exit code.
func TestSmbcExitCodes(t *testing.T) {
	addr, srv := serve(t)
	if err := srv.Share("disk", clientTree(t)); err != nil {
		t.Fatal(err)
	}
	good := credFile(t, "alice", "hunter2")
	bad := credFile(t, "alice", "wrong")
	for _, sub := range []string{"ls", "df", "du"} {
		cases := []struct {
			name string
			args []string
			code int
		}{
			{"bad name", []string{"--credentials-file", good, "not-a-unc"}, smbc.ExitUsage},
			{"no credentials", []string{"//" + addr + "/disk"}, smbc.ExitUsage},
			{"unreadable credentials", []string{"--credentials-file", "/nonexistent/cred", "//" + addr + "/disk"}, smbc.ExitUsage},
			{"wrong password", []string{"--credentials-file", bad, "//" + addr + "/disk"}, smbc.ExitAuth},
			{"no such share", []string{"--credentials-file", good, "//" + addr + "/nosuchshare"}, smbc.ExitTree},
			{"no such host", []string{"--credentials-file", good, "--connect-timeout", "2s", "//127.0.0.1:1/disk"}, smbc.ExitConnect},
		}
		for _, c := range cases {
			t.Run(sub+"/"+c.name, func(t *testing.T) {
				_, errb, code := smbcRun(t, append([]string{sub}, c.args...)...)
				if code != c.code {
					t.Fatalf("exit %d, want %d (%s)", code, c.code, errb)
				}
			})
		}
	}
	// a path that is not there
	if _, _, code := smbcRun(t, "ls", "--credentials-file", good, "//"+addr+"/disk/nodir"); code != smbc.ExitFailure {
		t.Errorf("ls of a missing directory: exit %d", code)
	}
	if _, _, code := smbcRun(t, "df", "--credentials-file", good, "//"+addr+"/disk/nodir"); code != smbc.ExitFailure {
		t.Errorf("df of a missing path: exit %d", code)
	}
	if _, _, code := smbcRun(t, "du", "--credentials-file", good, "//"+addr+"/disk/nodir"); code != smbc.ExitIncomplete {
		t.Errorf("du of a missing path: exit %d", code)
	}
}

// listFS cannot list one directory.
type listFS struct {
	*memFS
}

func (l listFS) ListDir(p string) ([]filesystem.DirEntry, error) {
	if strings.HasSuffix(p, "/b") {
		return nil, errors.New("directory unreadable")
	}
	return l.memFS.ListDir(p)
}

// du reports the directories it could not read, and says the total is a lower bound.
func TestSmbcDuSaysWhenItCouldNotRead(t *testing.T) {
	addr, srv := serve(t)
	if err := srv.Share("disk", listFS{clientTree(t)}); err != nil {
		t.Fatal(err)
	}
	out, errb, code := smbcRun(t, "du", "--credentials-file", credFile(t, "alice", "hunter2"), "//"+addr+"/disk")
	if code != smbc.ExitIncomplete {
		t.Fatalf("exit %d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(errb, "/a/b") {
		t.Fatalf("stderr does not name the directory:\n%s", errb)
	}
}
