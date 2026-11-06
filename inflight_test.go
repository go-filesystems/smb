// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
)

// readBody is the body of a READ: length, offset and file id at their places.
func readBody(of *openFile, off uint64, length uint32) []byte {
	b := make([]byte, 49)
	binary.LittleEndian.PutUint16(b, 49)
	binary.LittleEndian.PutUint32(b[4:], length)
	binary.LittleEndian.PutUint64(b[8:], off)
	copy(b[16:], of.id[:])
	return b
}

func TestWhichFramesMayRunBesideOthers(t *testing.T) {
	c, of := opened(t, &tinyFS{body: []byte("0123456789")}, "/file.txt", false)
	good := request(cmdRead, 1, readBody(of, 4, 8))
	sp, ok := c.readSpan(good)
	if !ok {
		t.Fatal("a READ of a plain file was not allowed to run beside others")
	}
	_ = sp

	if _, ok := c.readSpan(good[:headerLen+10]); ok {
		t.Error("a truncated READ was allowed")
	}
	if _, ok := c.readSpan(request(cmdEcho, 1, readBody(of, 0, 1))); ok {
		t.Error("an ECHO was allowed")
	}
	if _, ok := c.readSpan(append([]byte("not smb2 at all"), make([]byte, 80)...)); ok {
		t.Error("something that is not a message was allowed")
	}
	chained := request(cmdRead, 1, readBody(of, 0, 1))
	binary.LittleEndian.PutUint32(chained[offNextCommand:], 128)
	if _, ok := c.readSpan(chained); ok {
		t.Error("a compound chain was allowed: it is answered whole, in order")
	}
	// A handle that is not there, a directory and a pipe are all barriers: the
	// first two answer an error in order, the last has state of its own.
	gone := readBody(of, 0, 1)
	gone[16] = 99
	if _, ok := c.readSpan(request(cmdRead, 1, gone)); ok {
		t.Error("a READ of a closed handle was allowed")
	}
	of.dir = true
	if _, ok := c.readSpan(good); ok {
		t.Error("a READ of a directory was allowed")
	}
	of.dir, of.pipe = false, &pipe{}
	if _, ok := c.readSpan(good); ok {
		t.Error("a READ of a pipe was allowed")
	}
}

func TestInFlightResolution(t *testing.T) {
	for _, tc := range []struct{ in, want int }{{0, DefaultMaxInFlight}, {-1, 1}, {7, 7}} {
		if got := (&Server{MaxInFlight: tc.in}).maxInFlight(); got != tc.want {
			t.Errorf("MaxInFlight %d -> %d, want %d", tc.in, got, tc.want)
		}
	}
	for _, n := range []int{0, -3, 5} {
		s := New()
		s.MaxInFlightTotal = n
		if p := s.inflightPool(); p == nil || p != s.inflightPool() {
			t.Errorf("MaxInFlightTotal %d: pool %v", n, p)
		}
	}
}

func TestAFailedReplyClosesTheConnection(t *testing.T) {
	a, b := net.Pipe()
	b.Close() // the peer is gone: the write fails
	c := newConn(New(), a)
	if _, err := (frameSender{c}).Write([]byte("reply")); err == nil {
		t.Fatal("a write to a dead peer succeeded")
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Error("the connection was left open after a failed reply")
	}
}

func TestAPanicInARequestIsRecordedAndEndsTheConnection(t *testing.T) {
	c, of := opened(t, &tinyFS{body: []byte("0123456789")}, "/file.txt", false)
	of.share = nil // the READ dereferences it
	out, err := c.runner(request(cmdRead, 1, readBody(of, 0, 4)))(nil)
	if !errors.Is(err, errPanic) || out != nil {
		t.Fatalf("runner = %v, %v", out, err)
	}
	if c.panicked == nil {
		t.Fatal("the panic was not recorded")
	}
}

func TestPrefixedReaderHandsOutItsByteFirst(t *testing.T) {
	var p prefixed
	p.reset(bytes.NewReader([]byte("xyz")), 'a')
	if n, err := p.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = %d, %v", n, err)
	}
	buf := make([]byte, 4)
	if n, _ := p.Read(buf); n != 1 || buf[0] != 'a' {
		t.Fatalf("first Read = %d %q", n, buf)
	}
	if n, err := p.Read(buf); n != 3 || (err != nil && err != io.EOF) {
		t.Fatalf("second Read = %d, %v", n, err)
	}
}
