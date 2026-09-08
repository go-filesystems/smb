package smb_test

import (
	"bytes"
	"io"
	"os"
	"sort"
	"testing"

	fssmb "github.com/go-filesystems/smb"
)

// The mount, done by a client this project did not write: make a file, write
// it, read it back, list the directory, stat it, and remove it.
//
// It runs twice over two filesystems that differ in ONE capability -- one
// answers OpenFile and one does not -- because the fallback path is a
// different set of statements and a mount that works over one must work over
// the other.
func TestAFileGoesThereAndComesBack(t *testing.T) {
	for _, positional := range []bool{true, false} {
		name := "with positional access"
		if !positional {
			name = "with only whole-file access"
		}
		t.Run(name, func(t *testing.T) {
			mem := newMemFS(positional)
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

			want := bytes.Repeat([]byte("the quick brown fox "), 500) // 10 kB, several blocks
			if err := fs.WriteFile("greeting.txt", want, 0o644); err != nil {
				t.Fatalf("writing: %v", err)
			}
			got, err := fs.ReadFile("greeting.txt")
			if err != nil {
				t.Fatalf("reading: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("read back %d bytes of %d, and they differ", len(got), len(want))
			}
			// …and the driver underneath holds the same bytes, which is what
			// says the server wrote through rather than remembered.
			if inDriver, err := mem.ReadFile("/greeting.txt"); err != nil || !bytes.Equal(inDriver, want) {
				t.Errorf("the filesystem holds %d bytes (%v), not what was written", len(inDriver), err)
			}

			st, err := fs.Stat("greeting.txt")
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if st.Size() != int64(len(want)) {
				t.Errorf("stat says %d bytes, want %d", st.Size(), len(want))
			}
			if st.IsDir() {
				t.Error("stat says a file is a directory")
			}

			if err := fs.Mkdir("sub", 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := fs.WriteFile("sub/inner.txt", []byte("inside"), 0o644); err != nil {
				t.Fatalf("writing inside a directory: %v", err)
			}

			names := readdir(t, fs, ".")
			if want := []string{"greeting.txt", "sub"}; !equal(names, want) {
				t.Errorf("the root lists %v, want %v", names, want)
			}
			if names := readdir(t, fs, "sub"); !equal(names, []string{"inner.txt"}) {
				t.Errorf("sub lists %v", names)
			}

			if err := fs.Remove("greeting.txt"); err != nil {
				t.Errorf("removing: %v", err)
			}
			if _, err := fs.Stat("greeting.txt"); err == nil {
				t.Error("the file is still there after being removed")
			}
		})
	}
}

// A read at an offset is a read at that offset, and one past the end says so
// rather than returning zeros.
func TestReadingAtAnOffset(t *testing.T) {
	mem := newMemFS(true)
	addr, srv := serve(t)
	if err := srv.Share("disk", mem); err != nil {
		t.Fatal(err)
	}
	body := []byte("0123456789abcdefghij")
	if err := mem.WriteFile("/f.txt", body, 0o644); err != nil {
		t.Fatal(err)
	}
	s, done := dial(t, addr, "alice", "hunter2")
	defer done()
	fs, err := s.Mount("disk")
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Umount()

	f, err := fs.Open("f.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 5)
	if n, err := f.ReadAt(buf, 10); err != nil || n != 5 || string(buf) != "abcde" {
		t.Errorf("ReadAt(10) = %q, %d, %v", buf[:n], n, err)
	}
	if _, err := f.ReadAt(buf, int64(len(body))); err != io.EOF {
		t.Errorf("reading past the end returned %v, want io.EOF", err)
	}
}

// A share exported read-only refuses the write, and says which kind of refusal
// it is: the medium, not the permissions.
func TestAReadOnlyShareRefusesWrites(t *testing.T) {
	mem := newMemFS(true)
	if err := mem.WriteFile("/there.txt", []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr, srv := serve(t)
	if err := srv.Share("ro", mem, fssmb.ReadOnly()); err != nil {
		t.Fatal(err)
	}
	s, done := dial(t, addr, "alice", "hunter2")
	defer done()
	fs, err := s.Mount("ro")
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Umount()

	if got, err := fs.ReadFile("there.txt"); err != nil || string(got) != "hello" {
		t.Errorf("a read-only share did not serve a read: %q, %v", got, err)
	}
	if err := fs.WriteFile("new.txt", []byte("nope"), 0o644); err == nil {
		t.Error("a read-only share accepted a write")
	}
	if _, err := mem.ReadFile("/new.txt"); !os.IsNotExist(err) {
		t.Error("the refused write reached the filesystem anyway")
	}
}

// A path that climbs out of the share does not: the share is the root, and
// "\..\..\etc\passwd" resolves inside it or not at all.
func TestAPathCannotLeaveTheShare(t *testing.T) {
	mem := newMemFS(true)
	addr, srv := serve(t)
	if err := srv.Share("disk", mem); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile("/inside.txt", []byte("in"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, done := dial(t, addr, "alice", "hunter2")
	defer done()
	fs, err := s.Mount("disk")
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Umount()

	// Climbing out lands back at the root, where the file IS -- so the check
	// is that it resolves inside rather than that it fails, which is what a
	// filesystem does with "/../x".
	if got, err := fs.ReadFile(`..\..\..\inside.txt`); err != nil || string(got) != "in" {
		t.Errorf("a climbing path read %q, %v", got, err)
	}
	// A stream name is not a path, and this server has no streams.
	if _, err := fs.ReadFile("inside.txt:hidden:$DATA"); err == nil {
		t.Error("a stream name was accepted as a file")
	}
}

func readdir(t *testing.T, fs interface {
	ReadDir(string) ([]os.FileInfo, error)
}, dir string) []string {
	t.Helper()
	entries, err := fs.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
