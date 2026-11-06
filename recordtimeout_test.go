package smb

import (
	"net"
	"testing"
	"time"
)

func TestRecordTimeoutResolution(t *testing.T) {
	for _, tc := range []struct{ in, want time.Duration }{{0, DefaultRecordTimeout}, {-1, 0}, {time.Second, time.Second}} {
		if got := (&Server{RecordTimeout: tc.in}).recordTimeout(); got != tc.want {
			t.Errorf("RecordTimeout %v -> %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A client that sends part of a frame and stops loses its connection within
// the timeout, and the budget it held comes back: with a server-wide budget of
// ONE, a second client is then served.
func TestAHalfSentFrameReleasesTheBudgetAndTheConnection(t *testing.T) {
	srv := New()
	srv.MaxInFlightTotal = 1
	srv.RecordTimeout = 200 * time.Millisecond
	a, b := net.Pipe()
	defer a.Close()
	served := make(chan struct{})
	go func() { newConn(srv, b).serve(); close(served) }()

	// The header of a 100-byte frame, one byte of it, and then silence.
	if _, err := a.Write([]byte{0, 0, 0, 100, 0xFE}); err != nil {
		t.Fatal(err)
	}
	// The budget is spent while the frame is incomplete: a second connection
	// cannot take a slot.
	c, d := net.Pipe()
	defer c.Close()
	second := make(chan struct{})
	go func() { newConn(srv, d).serve(); close(second) }()
	go c.Write([]byte{0, 0, 0, 1, 0}) // starts a frame: needs the token
	select {
	case <-second:
		t.Fatal("a second connection was served while the first held the whole budget")
	case <-time.After(50 * time.Millisecond):
	}

	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("a half-sent frame kept its connection past RecordTimeout")
	}
	// The token is back: the second connection's frame (one byte, not an SMB2
	// message) is now read and refused, which ends that connection too.
	select {
	case <-second:
	case <-time.After(3 * time.Second):
		t.Fatal("the budget was not released when the half-sent frame was dropped")
	}
}
