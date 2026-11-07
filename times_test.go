package smb_test

import (
	"errors"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// timedFS is the memory filesystem plus the times capability.
type timedFS struct {
	*memFS
	times map[string]filesystem.FileTimes
}

func (f timedFS) Times(p string) (filesystem.FileTimes, error) {
	if ft, ok := f.times[p]; ok {
		return ft, nil
	}
	return filesystem.FileTimes{}, errors.New("no times")
}

// A client this project did not write reads back the times the driver records:
// the last-write time as the file's ModTime, from the single-file query and
// from a directory listing; and a time the format does not keep is not
// replaced by NOW.
func TestTheClientSeesTheTimesTheFilesystemRecords(t *testing.T) {
	mem := newMemFS(true)
	if err := mem.WriteFile("/old.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile("/none.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile("/unlisted.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2019, 3, 4, 5, 6, 8, 0, time.UTC)
	tfs := timedFS{memFS: mem, times: map[string]filesystem.FileTimes{
		"/old.txt": {
			Mtime: filesystem.NewTimestamp(mtime, 2*time.Second),
			Atime: filesystem.NewTimestamp(mtime.Add(24*time.Hour), 24*time.Hour),
		},
		"/none.txt": {}, // a driver that keeps none of the four
		"/":         {Mtime: filesystem.NewTimestamp(mtime, time.Nanosecond)},
	}}
	addr, srv := serve(t)
	if err := srv.Share("disk", tfs); err != nil {
		t.Fatal(err)
	}
	s, done := dial(t, addr, "alice", "hunter2")
	defer done()
	fs, err := s.Mount("disk")
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Umount()

	st, err := fs.Stat("old.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !st.ModTime().Equal(mtime) {
		t.Errorf("Stat ModTime = %v, want %v", st.ModTime(), mtime)
	}
	list, err := fs.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]time.Time{}
	for _, e := range list {
		seen[e.Name()] = e.ModTime()
	}
	if got := seen["old.txt"]; !got.Equal(mtime) {
		t.Errorf("listing ModTime = %v, want %v", got, mtime)
	}
	// Not recorded is 0 on the wire -- never NOW. How a client shows 0 is its
	// own: Windows shows 1601, and this one (go-smb2) overflows time.Duration
	// converting it and shows the year 2185. Either way it is not "now".
	if got := seen["none.txt"]; time.Since(got) > -time.Minute && time.Since(got) < time.Minute {
		t.Errorf("none.txt: unrecorded ModTime = %v, looks like NOW", got)
	}
	// A driver whose Times call fails keeps the old behaviour for that path.
	if got := seen["unlisted.txt"]; time.Since(got) < -time.Minute || time.Since(got) > time.Minute {
		t.Errorf("unlisted.txt: ModTime = %v, want about now", got)
	}
}

// A driver without the capability keeps the old behaviour: the times are now.
func TestWithoutTheCapabilityTheTimesAreNow(t *testing.T) {
	mem := newMemFS(true)
	if err := mem.WriteFile("/f.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr, srv := serve(t)
	if err := srv.Share("disk", mem); err != nil {
		t.Fatal(err)
	}
	s, done := dial(t, addr, "alice", "hunter2")
	defer done()
	fs, err := s.Mount("disk")
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Umount()
	st, err := fs.Stat("f.txt")
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(st.ModTime()); d < -time.Minute || d > time.Minute {
		t.Errorf("ModTime = %v, expected about now", st.ModTime())
	}
}
