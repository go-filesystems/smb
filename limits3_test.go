package smb

import (
	"net"
	"testing"
	"time"
)

// A client that drops with a handle open must not leave a clock behind: the idle
// timer re-arms itself for as long as a handle is open, and it holds the
// connection, so one that outlived serve would keep every dropped connection
// alive for ever.
func TestNoClockOutlivesItsConnection(t *testing.T) {
	srv := New()
	srv.PreAuthTimeout = -1
	srv.IdleTimeout = 15 * time.Millisecond
	a, peer := net.Pipe()
	c := newConn(srv, a)
	c.counted.Store(true)
	srv.admit(c)
	c.markAuthenticated() // arms the idle clock
	c.nOpen.Add(1)        // the client has a file open, and (teardown closes files directly) will not close it
	served := make(chan struct{})
	go func() { c.serve(); close(served) }()
	// Let the idle clock fire and re-arm at least once while the connection lives.
	time.Sleep(60 * time.Millisecond)
	if c.idleTimer.Load() == nil {
		t.Fatal("the idle clock is not running on a live connection with a handle open")
	}
	peer.Close() // the client drops
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return")
	}
	if c.idleTimer.Load() != nil || c.preTimer.Load() != nil {
		t.Error("a clock is still held by the connection after serve returned")
	}
	// And it cannot be armed again by a check that was already running.
	c.armIdle(time.Millisecond)
	c.idleCheck()
	c.startPreAuthClock()
	time.Sleep(40 * time.Millisecond)
	if c.idleTimer.Load() != nil || c.preTimer.Load() != nil {
		t.Error("a clock was re-armed on a connection that has ended")
	}
}

// Going back among the unauthenticated would exceed a cap that is full: the
// connection goes instead.
func TestLoggingOffIntoAFullPreAuthCapClosesTheConnection(t *testing.T) {
	srv := exchangeConn(t, dialect302).srv
	srv.MaxPreAuthConnections = 1
	srv.PreAuthTimeout = -1
	srv.IdleTimeout = -1
	a, peer := net.Pipe()
	c := newConn(srv, a)
	c.dialect = dialect302
	c.counted.Store(true)
	srv.admit(c)
	s := &setupper{t: t, c: c}
	s.leg2(s.leg1(0), "alice", "hunter2")
	if srv.preAuth != 0 {
		t.Fatalf("%d unauthenticated", srv.preAuth)
	}
	// Somebody else takes the one place.
	other, _ := fakeConn(srv)
	if !srv.admit(other) {
		t.Fatal("the place was not free")
	}
	for sid := range c.sessions {
		c.dispatchChain(requestIn(cmdLogoff, sid, 0, []byte{4, 0, 0, 0}))
	}
	if srv.preAuth != 1 {
		t.Errorf("%d unauthenticated: the connection exceeded the cap by returning to it", srv.preAuth)
	}
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("the connection was not closed: %v", err)
	}
}
