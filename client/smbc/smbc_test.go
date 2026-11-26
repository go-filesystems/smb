package smbc

import (
	"os"
	"testing"

	"github.com/go-filesystems/smb/client"
)

func TestSize(t *testing.T) {
	cases := []struct {
		n     uint64
		human bool
		want  string
	}{
		{0, true, "0B"},
		{1023, true, "1023B"},
		{1024, true, "1.0K"},
		{1536, true, "1.5K"},
		{1 << 20, true, "1.0M"},
		{1 << 30, true, "1.0G"},
		{1 << 60, true, "1.0E"},
		{1<<64 - 1, true, "16.0E"},
		{1024, false, "1024"},
	}
	for _, c := range cases {
		if got := size(c.n, c.human); got != c.want {
			t.Errorf("size(%d, %v) = %q, want %q", c.n, c.human, got, c.want)
		}
	}
}

func TestExitFor(t *testing.T) {
	// each step has its own code, and an unknown one is a plain failure
	seen := map[int]string{}
	for _, s := range []struct {
		step string
		code int
	}{{"connect", ExitConnect}, {"auth", ExitAuth}, {"tree", ExitTree}, {"read", ExitRead},
		{"write-create", ExitWrite}, {"write-verify", ExitWrite}, {"write-delete", ExitWrite}, {"other", ExitFailure}} {
		if got := exitFor(client.Step(s.step)); got != s.code {
			t.Errorf("%s: %d, want %d", s.step, got, s.code)
		}
		seen[s.code] = s.step
	}
	if len(seen) != 6 {
		t.Errorf("the codes are not distinct: %v", seen)
	}
}

func TestMainExitsWithTheCodeOfTheError(t *testing.T) {
	oldArgs, oldExit := os.Args, osExit
	defer func() { os.Args, osExit = oldArgs, oldExit }()
	var got []int
	osExit = func(c int) { got = append(got, c) }

	os.Args = []string{"smbc", "--help"}
	Main()
	if len(got) != 0 {
		t.Fatalf("--help exited with %v", got)
	}
	os.Args = []string{"smbc", "no-such-command"}
	Main()
	os.Args = []string{"smbc", "check", "not-a-unc"}
	Main()
	if len(got) != 2 || got[0] != ExitFailure || got[1] != ExitUsage {
		t.Fatalf("exit codes %v, want [%d %d]", got, ExitFailure, ExitUsage)
	}
}
