package smb

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// The limits, driven directly: no sockets, no clock.

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func limitedServer(total, pre int) *Server {
	s := New()
	s.MaxConnections, s.MaxPreAuthConnections = total, pre
	s.PreAuthTimeout = -1
	return s
}

func fakeConn(s *Server) (*conn, net.Conn) {
	a, b := net.Pipe()
	c := newConn(s, a)
	c.counted.Store(true)
	return c, b
}

func TestTheDefaultsAreFiniteAndNegativeMeansNone(t *testing.T) {
	s := New()
	if s.maxConnections() != DefaultMaxConnections || s.maxPreAuth() != DefaultMaxPreAuthConnections || s.preAuthTimeout() != DefaultPreAuthTimeout {
		t.Errorf("defaults: %d %d %v", s.maxConnections(), s.maxPreAuth(), s.preAuthTimeout())
	}
	if DefaultMaxConnections <= 0 || DefaultMaxPreAuthConnections <= 0 || DefaultPreAuthTimeout <= 0 || DefaultMaxPreAuthConnections > DefaultMaxConnections {
		t.Error("a default is not a sane bound")
	}
	s.MaxConnections, s.MaxPreAuthConnections, s.PreAuthTimeout = -1, -1, -1
	if s.maxConnections() != 0 || s.maxPreAuth() != 0 || s.preAuthTimeout() != 0 {
		t.Error("a negative value is not 'no limit'")
	}
	s.MaxConnections, s.MaxPreAuthConnections, s.PreAuthTimeout = 7, 3, time.Second
	if s.maxConnections() != 7 || s.maxPreAuth() != 3 || s.preAuthTimeout() != time.Second {
		t.Error("an explicit value was not used")
	}
}

func TestTheUnauthenticatedCapAndAuthenticationFreeingASlot(t *testing.T) {
	s := limitedServer(0, 3)
	var cs []*conn
	for i := 0; i < 3; i++ {
		c, _ := fakeConn(s)
		if !s.admit(c) {
			t.Fatalf("connection %d refused below the cap", i)
		}
		cs = append(cs, c)
	}
	c4, _ := fakeConn(s)
	if s.admit(c4) {
		t.Fatal("a fourth unauthenticated connection was admitted")
	}
	// One authenticates: its place is given back, and another may come.
	cs[0].markAuthenticated()
	cs[0].markAuthenticated() // idempotent
	if s.preAuth != 2 {
		t.Fatalf("%d unauthenticated after one authenticated, want 2", s.preAuth)
	}
	if !s.admit(c4) {
		t.Error("a place freed by an authentication was not reusable")
	}
	// Authenticated connections are not bound by the unauthenticated cap.
	for i := 0; i < 10; i++ {
		c, _ := fakeConn(s)
		s.preAuth = 0 // make room, as authentications would
		if !s.admit(c) {
			t.Fatal("refused with room")
		}
		c.markAuthenticated()
	}
	// A connection that ends while unauthenticated gives its place back too.
	s.preAuth = 0
	c, _ := fakeConn(s)
	s.admit(c)
	s.release(c)
	s.release(c) // twice is harmless
	if s.preAuth != 0 {
		t.Errorf("%d held after a release", s.preAuth)
	}
}

func TestTheTotalCap(t *testing.T) {
	s := limitedServer(2, -1)
	a, _ := fakeConn(s)
	b, _ := fakeConn(s)
	c, _ := fakeConn(s)
	if !s.admit(a) || !s.admit(b) {
		t.Fatal("refused below the cap")
	}
	if s.admit(c) {
		t.Fatal("a third connection was admitted")
	}
	a.markAuthenticated() // authenticating does not free a place in the TOTAL
	if s.admit(c) {
		t.Fatal("authentication freed a place in the total")
	}
	s.release(a)
	if !s.admit(c) {
		t.Error("an ended connection's place was not reusable")
	}
}

// The log says it once per burst of refusals, and again after somebody got in.
func TestTheLimitIsLoggedOncePerBurst(t *testing.T) {
	s := limitedServer(1, -1)
	var buf syncBuf
	s.Logger = slog.New(slog.NewTextHandler(&buf, nil))
	in, _ := fakeConn(s)
	s.admit(in)
	for i := 0; i < 20; i++ {
		c, _ := fakeConn(s)
		s.admit(c)
	}
	if n := strings.Count(buf.String(), "limit reached"); n != 1 {
		t.Fatalf("a burst of 20 refusals logged %d times, want once", n)
	}
	s.release(in)
	again, _ := fakeConn(s)
	if !s.admit(again) {
		t.Fatal("not admitted after a release")
	}
	for i := 0; i < 5; i++ {
		c, _ := fakeConn(s)
		s.admit(c)
	}
	if n := strings.Count(buf.String(), "limit reached"); n != 2 {
		t.Errorf("a second burst: %d lines in all, want 2", n)
	}
	if s.dropped != 25 {
		t.Errorf("%d refusals counted, want 25", s.dropped)
	}
}

// The clock: a connection that has not authenticated in time is closed; one that
// has, is not; and the timer is gone when the connection is.
func TestThePreAuthClock(t *testing.T) {
	s := New()
	s.PreAuthTimeout = 30 * time.Millisecond
	silent, peer := fakeConn(s)
	silent.startPreAuthClock()
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("the silent connection: %v, want it closed by the server", err)
	}

	authed, peer2 := fakeConn(s)
	authed.startPreAuthClock()
	authed.markAuthenticated()
	peer2.SetReadDeadline(time.Now().Add(120 * time.Millisecond)) // four timeouts
	if _, err := peer2.Read(make([]byte, 1)); err == nil || !isTimeout(err) {
		t.Errorf("the authenticated connection: %v, want it left open (the read to time out)", err)
	}

	s.PreAuthTimeout = -1
	never, _ := fakeConn(s)
	never.startPreAuthClock()
	if never.preTimer.Load() != nil {
		t.Error("a clock was started although the timeout is switched off")
	}
}
