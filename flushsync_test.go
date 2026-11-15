package smb

import (
	"errors"
	"testing"
)

// syncingFS is tinyFS with a filesystem-level Sync, as (*hfsplus.Volume) has.
type syncingFS struct {
	tinyFS
	synced int
	err    error
}

func (f *syncingFS) Sync() error { f.synced++; return f.err }

// A FLUSH on a handle that has no WritableFile reaches the filesystem's own
// Sync, so a driver that holds what it accepted (hfsplus at lazy or mounted
// durability) puts it on the medium before the client is told it is flushed.
// A failure is STATUS_UNEXPECTED_IO_ERROR, never success.
func TestFlushWithoutAWritableFileSyncsTheFilesystem(t *testing.T) {
	fs := &syncingFS{tinyFS: tinyFS{body: []byte("hello")}}
	c, of := opened(t, fs, "/file.txt", false)
	if st := statusOf(t, mustDispatch(t, c, cmdFlush, flushBody(of))); st != statusSuccess {
		t.Fatalf("flush answered %#x", st)
	}
	if fs.synced != 1 {
		t.Errorf("the filesystem was synced %d times, want 1", fs.synced)
	}
	fs.err = errors.New("disk gone")
	if st := statusOf(t, mustDispatch(t, c, cmdFlush, flushBody(of))); st != statusIOError {
		t.Errorf("a failed sync answered %#x, want STATUS_UNEXPECTED_IO_ERROR", st)
	}

	// A handle that cannot write has nothing to flush.
	fs.err, fs.synced = nil, 0
	c, of = opened(t, fs, "/file.txt", true)
	if st := statusOf(t, mustDispatch(t, c, cmdFlush, flushBody(of))); st != statusSuccess || fs.synced != 0 {
		t.Errorf("read-only handle: status %#x, synced %d", st, fs.synced)
	}
}
