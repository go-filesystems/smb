package smb

import (
	"bytes"
	"testing"
)

// FuzzReadFrame feeds the frame reader whatever a peer can send before it has
// authenticated: it must return a body no larger than the limit or an error,
// never panic, and never read more than it was given.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 3, 1, 2, 3})
	f.Add([]byte{0, 0, 0, 100, 1})
	f.Add([]byte{0, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{1, 0, 0, 1, 0})
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		body, err := readFrame(bytes.NewReader(data))
		if err == nil && (len(body) == 0 || len(body) > maxMessageLen || len(body) > len(data)) {
			t.Fatalf("readFrame returned %d bytes of %d with no error", len(body), len(data))
		}
	})
}

// FuzzReadSpan feeds the concurrency classifier arbitrary frames: it must
// not panic whatever the header and body say.
func FuzzReadSpan(f *testing.F) {
	f.Add(make([]byte, 120))
	f.Add([]byte("\xfeSMB"))
	f.Fuzz(func(t *testing.T, msg []byte) {
		c := newConn(New(), nil)
		c.readSpan(msg)
	})
}
