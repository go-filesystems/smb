package smb_test

import (
	"os"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	fssmb "github.com/go-filesystems/smb"
)

// settableFS is the memory filesystem that records the access and write times
// of every file, and lets them be set: MetadataSetter and TimesReader.
type settableFS struct {
	*memFS
	at, mt map[string]time.Time
}

func newSettableFS() *settableFS {
	return &settableFS{memFS: newMemFS(true), at: map[string]time.Time{}, mt: map[string]time.Time{}}
}

func (f *settableFS) Chmod(string, os.FileMode) error    { return nil }
func (f *settableFS) Chown(string, uint32, uint32) error { return nil }
func (f *settableFS) Chtimes(p string, a, m time.Time) error {
	if _, err := f.Stat(p); err != nil {
		return err
	}
	if !a.IsZero() {
		f.at[p] = a
	}
	if !m.IsZero() {
		f.mt[p] = m
	}
	return nil
}
func (f *settableFS) Times(p string) (filesystem.FileTimes, error) {
	if _, err := f.Stat(p); err != nil {
		return filesystem.FileTimes{}, err
	}
	return filesystem.FileTimes{
		Atime: filesystem.NewTimestamp(f.at[p], time.Nanosecond),
		Mtime: filesystem.NewTimestamp(f.mt[p], time.Nanosecond),
	}, nil
}

// A client this project did not write sets the times and reads them back:
// the next read shows what was set, not the old time (go-filesystems/smb#45).
func TestChtimesThroughGoSMB2(t *testing.T) {
	fsys := newSettableFS()
	if err := fsys.WriteFile("/f.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	fsys.at["/f.txt"], fsys.mt["/f.txt"] = old.Add(-time.Hour), old.Add(-time.Hour)

	addr, srv := serve(t)
	if err := srv.Share("disk", fsys); err != nil {
		t.Fatal(err)
	}
	s, done := dial(t, addr, "alice", "hunter2")
	defer done()
	share, err := s.Mount("disk")
	if err != nil {
		t.Fatal(err)
	}
	defer share.Umount()

	atime := time.Date(2005, 6, 7, 8, 9, 10, 0, time.UTC)
	if err := share.Chtimes("f.txt", atime, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	st, err := share.Stat("f.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !st.ModTime().Equal(old) {
		t.Errorf("ModTime = %v, want %v", st.ModTime(), old)
	}
	if got := fsys.at["/f.txt"]; !got.Equal(atime) {
		t.Errorf("the driver holds atime %v, want %v", got, atime)
	}
}

// With TimesRefuse, a driver that cannot set times answers an error, not
// success: a backup tool must not believe the times were kept. Under the
// default (TimesIgnore) the same call succeeds and drops them.
func TestChtimesWithoutTheSetterIsAnError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		opts    []fssmb.ShareOption
		wantErr bool
	}{
		{"refuse", []fssmb.ShareOption{fssmb.UnstorableTimes(fssmb.TimesRefuse)}, true},
		{"default", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chtimesNoSetter(t, tc.opts, tc.wantErr)
		})
	}
}

func chtimesNoSetter(t *testing.T, opts []fssmb.ShareOption, wantErr bool) {
	mem := newMemFS(true)
	if err := mem.WriteFile("/f.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr, srv := serve(t)
	if err := srv.Share("disk", mem, opts...); err != nil {
		t.Fatal(err)
	}
	s, done := dial(t, addr, "alice", "hunter2")
	defer done()
	share, err := s.Mount("disk")
	if err != nil {
		t.Fatal(err)
	}
	defer share.Umount()
	if err := share.Chtimes("f.txt", time.Now(), time.Now()); (err != nil) != wantErr {
		t.Fatalf("Chtimes on a driver with no way to set a time: err = %v, want error %v", err, wantErr)
	}
}
