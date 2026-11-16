package smb

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// ─── accepting ───────────────────────────────────────────────────────────────

type tempErr struct{}

func (tempErr) Error() string   { return "accept: too many open files (test)" }
func (tempErr) Timeout() bool   { return false }
func (tempErr) Temporary() bool { return true }

// scriptedListener fails to accept a given number of times, with a given error,
// then hands out one connection, then blocks until closed.
type scriptedListener struct {
	mu     sync.Mutex
	fails  int
	err    error
	times  []time.Time
	given  bool
	again  chan struct{} // closed when Accept is called after the connection was given
	closed chan struct{}
	conn   net.Conn
}

func newScripted(fails int, err error) *scriptedListener {
	a, _ := net.Pipe()
	return &scriptedListener{fails: fails, err: err, again: make(chan struct{}), closed: make(chan struct{}), conn: a}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.times = append(l.times, time.Now())
	switch {
	case l.fails > 0:
		l.fails--
		err := l.err
		l.mu.Unlock()
		return nil, err
	case !l.given:
		l.given = true
		l.mu.Unlock()
		return l.conn, nil
	}
	select {
	case <-l.again:
	default:
		close(l.again)
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *scriptedListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}
func (l *scriptedListener) Addr() net.Addr { return &net.TCPAddr{} }

// A failure to accept one connection -- out of descriptors, an aborted connection --
// is retried with a growing wait, and the server carries on: it used to return from
// Serve, and every connection after it was refused for good.
func TestAcceptRetriesTemporaryErrors(t *testing.T) {
	s := limitedServer(0, -1)
	ln := newScripted(5, tempErr{})
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	select {
	case <-ln.again:
	case err := <-done:
		t.Fatalf("Serve returned %v after a temporary error", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the connection after the failures was never accepted")
	}
	s.mu.Lock()
	held := len(s.conns)
	s.mu.Unlock()
	if held != 1 {
		t.Errorf("%d connections held, want the one that was accepted after the failures", held)
	}
	// The waits grow: 5 ms, 10, 20, 40, 80 at least.
	ln.mu.Lock()
	times := append([]time.Time(nil), ln.times...)
	ln.mu.Unlock()
	want := 5 * time.Millisecond
	for i := 1; i <= 5; i++ {
		if gap := times[i].Sub(times[i-1]); gap < want {
			t.Errorf("wait %d was %v, want at least %v", i, gap, want)
		}
		want *= 2
	}
	s.Close()
	if err := <-done; err != nil {
		t.Errorf("Serve returned %v after Close", err)
	}
}

// Only a closed listener, or an error that is not temporary, ends Serve.
func TestAcceptEndsOnAnErrorThatIsNotTemporary(t *testing.T) {
	s := limitedServer(0, -1)
	boom := errors.New("the listener is broken")
	if err := s.Serve(newScripted(1, boom)); !errors.Is(err, boom) {
		t.Errorf("Serve returned %v, want the listener's own error", err)
	}
}

// Close wakes a loop that is waiting to try again: it does not sit out the wait.
func TestCloseEndsAnAcceptLoopThatIsBackingOff(t *testing.T) {
	s := limitedServer(0, -1)
	ln := newScripted(1<<30, tempErr{})
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	// Let the waits grow to their cap, then close: Serve must return at once.
	for {
		ln.mu.Lock()
		n := len(ln.times)
		ln.mu.Unlock()
		if n >= 10 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	s.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
	if took := time.Since(start); took > 900*time.Millisecond {
		t.Errorf("Close took %v: the loop sat out its wait", took)
	}
}

// ─── descriptors ─────────────────────────────────────────────────────────────

func TestTheDefaultCapRespectsTheDescriptorLimit(t *testing.T) {
	for _, tc := range []struct {
		soft  uint64
		known bool
		want  int
	}{
		{256, true, 192},    // macOS's default soft limit
		{1024, true, 768},   // Linux's usual
		{4096, true, 1024},  // above the default: the default
		{65536, true, 1024}, //
		{0, true, 1024},     // "0" is no information
		{256, false, 1024},  // not known: nothing to respect
		{4, true, 8},        // never below a floor
		{1 << 40, true, 1024},
	} {
		if got := defaultMaxConnections(tc.soft, tc.known); got != tc.want {
			t.Errorf("soft %d known %v: %d, want %d", tc.soft, tc.known, got, tc.want)
		}
	}
	// And an explicit MaxConnections is never second-guessed.
	s := New()
	s.MaxConnections = 5000
	if s.maxConnections() != 5000 {
		t.Error("an explicit cap was changed")
	}
}

// ─── the places a connection holds ───────────────────────────────────────────

func TestAuthenticatingFreesTheUnauthenticatedPlace(t *testing.T) {
	s := &setupper{t: t, c: exchangeConn(t, dialect302)}
	s.c.srv.PreAuthTimeout = -1
	s.c.srv.IdleTimeout = -1
	s.c.counted.Store(true)
	if !s.c.srv.admit(s.c) {
		t.Fatal("not admitted")
	}
	if s.c.srv.preAuth != 1 {
		t.Fatalf("%d unauthenticated after admission", s.c.srv.preAuth)
	}
	id := s.leg1(0)
	if st := s.leg2(id, "alice", "hunter2"); st != statusSuccess {
		t.Fatalf("login: %#x", st)
	}
	if s.c.srv.preAuth != 0 || !s.c.authed.Load() {
		t.Errorf("after a successful SESSION_SETUP: %d unauthenticated, authed=%v", s.c.srv.preAuth, s.c.authed.Load())
	}
}

// The last session logging off puts the connection back among the
// unauthenticated, with the clock started over: valid credentials cannot take
// every slot by logging in and off.
func TestLoggingOffTheLastSessionReturnsToPreAuth(t *testing.T) {
	a, peer := net.Pipe()
	srv := exchangeConn(t, dialect302).srv
	srv.PreAuthTimeout = 40 * time.Millisecond
	srv.IdleTimeout = -1
	c := newConn(srv, a)
	c.dialect = dialect302
	c.counted.Store(true)
	srv.admit(c)
	s := &setupper{t: t, c: c}
	one := s.leg1(0)
	s.leg2(one, "alice", "hunter2")
	two := s.leg1(0)
	s.leg2(two, "alice", "hunter2")
	if srv.preAuth != 0 {
		t.Fatalf("%d unauthenticated with two sessions", srv.preAuth)
	}
	logoff := func(sid uint64) {
		r := &requester{c: c, next: s.next}
		m := requestIn(cmdLogoff, sid, 0, []byte{4, 0, 0, 0})
		if _, err := c.dispatchChain(m); err != nil {
			t.Fatal(err)
		}
		_ = r
	}
	logoff(one)
	if srv.preAuth != 0 || !c.authed.Load() {
		t.Fatalf("a session is left, and the connection went back to pre-auth: %d %v", srv.preAuth, c.authed.Load())
	}
	logoff(two)
	if srv.preAuth != 1 || c.authed.Load() {
		t.Fatalf("no session is left: %d unauthenticated, authed=%v, want 1 and false", srv.preAuth, c.authed.Load())
	}
	// And the pre-authentication clock runs again: the silent connection is closed.
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("a connection with no session was not closed by the pre-auth clock: %v", err)
	}
}

// The idle clock: an authenticated connection that has said nothing, holds no
// handle and waits on nothing is closed; one that holds a handle, or waits, is not;
// and a request puts the clock back.
func TestTheIdleClock(t *testing.T) {
	srv := New()
	srv.PreAuthTimeout = -1
	srv.IdleTimeout = 40 * time.Millisecond
	open := func() (*conn, net.Conn) {
		a, b := net.Pipe()
		c := newConn(srv, a)
		c.counted.Store(true)
		c.markAuthenticated()
		return c, b
	}
	closedWithin := func(peer net.Conn, d time.Duration) bool {
		peer.SetReadDeadline(time.Now().Add(d))
		_, err := peer.Read(make([]byte, 1))
		return err != nil && !isTimeout(err)
	}

	idle, p1 := open()
	_ = idle
	if !closedWithin(p1, 5*time.Second) {
		t.Error("an idle authenticated connection was not closed")
	}

	holding, p2 := open()
	holding.nOpen.Add(1)
	if closedWithin(p2, 200*time.Millisecond) { // five idle periods
		t.Error("a connection holding an open handle was closed")
	}

	waiting, p3 := open()
	waiting.mu.Lock()
	waiting.waiting[1] = &pendingOp{}
	waiting.mu.Unlock()
	if closedWithin(p3, 200*time.Millisecond) {
		t.Error("a connection with an operation pending was closed")
	}
	// Once the handle is closed and the wait ends, it is idle like any other.
	holding.nOpen.Add(-1)
	if !closedWithin(p2, 5*time.Second) {
		t.Error("a connection whose last handle closed was never closed for being idle")
	}

	busy, p4 := open()
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) { // a request every 10 ms for six periods
		busy.touch()
		time.Sleep(10 * time.Millisecond)
	}
	if closedWithin(p4, 10*time.Millisecond) {
		t.Error("a connection that kept making requests was closed")
	}

	// Switched off, and not armed for an unauthenticated connection.
	// (A server of its own: the clocks of the others still read this one's fields.)
	srv2 := New()
	srv2.PreAuthTimeout = -1
	srv2.IdleTimeout = -1
	a, p5 := net.Pipe()
	off := newConn(srv2, a)
	off.counted.Store(true)
	off.markAuthenticated()
	if closedWithin(p5, 150*time.Millisecond) {
		t.Error("the idle clock ran although it is switched off")
	}
}
