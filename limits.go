// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"log/slog"
	"sync/atomic"
	"time"
)

// Limits on connections, and on what a connection may hold before it has proved
// who it is.
//
// A connection costs a goroutine, buffers, a credit window and a place in the
// server's tables, and until somebody has authenticated on it, nothing has been
// earned. [MS-SMB2] leaves the policy to the server (3.3.5.1 on accepting a
// transport connection); a server that leaves loopback needs one, or a peer that
// opens connections and says nothing holds them for as long as it likes.
//
// Three bounds, each with a default and each switched off by a negative value:
// the connections open, the ones among them that have no authenticated session,
// and how long one of those may stay silent of authentication.
const (
	// DefaultMaxConnections is how many connections the server holds at once.
	DefaultMaxConnections = 1024
	// DefaultMaxPreAuthConnections is how many of them may have no authenticated
	// session. A client that is logging in holds a slot for a second or two; a
	// macOS mount uses two connections; a few hundred at once is a very large site
	// all mounting in the same instant.
	DefaultMaxPreAuthConnections = 256
	// DefaultPreAuthTimeout is how long a connection may take to authenticate
	// before it is closed. NTLM is two round trips, so a minute is generous.
	DefaultPreAuthTimeout = time.Minute
)

func resolveLimit(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0 // no limit
	}
	return v
}

// DefaultIdleTimeout is how long an authenticated connection with no open handle
// and no operation pending may go without a request before it is closed. It is
// Windows' own "autodisconnect" (15 minutes), and a client whose mount is merely
// idle reconnects transparently; what it stops is valid credentials holding a
// slot forever.
const DefaultIdleTimeout = 15 * time.Minute

func (s *Server) idleTimeout() time.Duration {
	switch {
	case s.IdleTimeout == 0:
		return DefaultIdleTimeout
	case s.IdleTimeout < 0:
		return 0
	}
	return s.IdleTimeout
}

// defaultMaxConnections is the default for MaxConnections on a process whose
// descriptor limit is soft: every connection is a descriptor, and so is every file
// a driver opens, so a default above the limit is a cap that EMFILE reaches first.
// It keeps a quarter of the descriptors for everything else. (macOS's default soft
// limit is 256, which makes this 192; Linux's is usually 1024 or more.) Where the
// limit is unknown there is nothing to respect.
func defaultMaxConnections(soft uint64, known bool) int {
	if !known || soft == 0 || soft >= 1<<31 {
		return DefaultMaxConnections
	}
	return int(min(uint64(DefaultMaxConnections), max(soft*3/4, 8)))
}

func (s *Server) maxConnections() int {
	soft, known := fdLimit()
	return resolveLimit(s.MaxConnections, defaultMaxConnections(soft, known))
}
func (s *Server) maxPreAuth() int {
	return resolveLimit(s.MaxPreAuthConnections, DefaultMaxPreAuthConnections)
}

func (s *Server) preAuthTimeout() time.Duration {
	switch {
	case s.PreAuthTimeout == 0:
		return DefaultPreAuthTimeout
	case s.PreAuthTimeout < 0:
		return 0
	}
	return s.PreAuthTimeout
}

// admit says whether a new connection may be held, and counts it if so. It is
// called with the accept loop's connection before anything is spent on it.
func (s *Server) admit(c *conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	maxTotal, maxPre := s.maxConnections(), s.maxPreAuth()
	if (maxTotal > 0 && len(s.conns) >= maxTotal) || (maxPre > 0 && s.preAuth >= maxPre) {
		s.dropped++
		first := !s.dropping
		s.dropping = true
		if first {
			s.logLimit(len(s.conns), s.preAuth)
		}
		return false
	}
	s.dropping = false // somebody got in: the next refusal starts a new burst
	s.conns[c] = struct{}{}
	s.preAuth++
	return true
}

// logLimit says, once per burst of refusals, that the limit was reached.
func (s *Server) logLimit(open, preAuth int) {
	l := slog.Default()
	if s.Logger != nil {
		l = s.Logger
	}
	l.Warn("smb connection refused: limit reached",
		"open", open, "unauthenticated", preAuth,
		"max_connections", s.maxConnections(), "max_preauth_connections", s.maxPreAuth())
}

// logAcceptError says that accepting failed for a reason that will pass, and how
// long the loop waits before trying again. The loop calls it once per streak of
// failures, not once per attempt.
func (s *Server) logAcceptError(err error, wait time.Duration) {
	l := slog.Default()
	if s.Logger != nil {
		l = s.Logger
	}
	l.Warn("smb accept failed, retrying", "error", err, "wait", wait)
}

// release forgets a connection that has ended, and gives back its place among the
// unauthenticated if it still held one.
func (s *Server) release(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
	if c.counted.CompareAndSwap(true, false) {
		s.preAuth--
	}
}

// markAuthenticated is called when a session is established on the connection: it
// stops the clock and frees the connection's place among the unauthenticated.
func (c *conn) markAuthenticated() {
	if c.authed.Swap(true) {
		return
	}
	if t := c.preTimer.Swap(nil); t != nil {
		t.Stop()
	}
	if c.counted.CompareAndSwap(true, false) {
		c.srv.mu.Lock()
		c.srv.preAuth--
		c.srv.mu.Unlock()
	}
	c.touch()
	if d := c.srv.idleTimeout(); d > 0 {
		c.armIdle(d)
	}
}

// markUnauthenticated is the other way: the last session on the connection has
// logged off, so it holds nothing it has earned. It counts as unauthenticated
// again -- a slot of the pre-authentication cap, and the pre-authentication clock
// starts over -- or valid credentials could take every slot by logging in and off.
func (c *conn) markUnauthenticated() {
	if !c.authed.Swap(false) {
		return
	}
	if t := c.idleTimer.Swap(nil); t != nil {
		t.Stop()
	}
	if c.counted.CompareAndSwap(false, true) {
		c.srv.mu.Lock()
		over := c.srv.maxPreAuth() > 0 && c.srv.preAuth >= c.srv.maxPreAuth()
		if !over {
			c.srv.preAuth++
		}
		c.srv.mu.Unlock()
		if over {
			// The unauthenticated cap is full: this connection would exceed it by
			// returning to it, so it goes instead (a client reconnects).
			c.counted.Store(false)
			c.nc.Close()
			return
		}
	}
	c.startPreAuthClock()
}

// startPreAuthClock closes the connection if nobody has authenticated on it in
// time.
func (c *conn) startPreAuthClock() {
	d := c.srv.preAuthTimeout()
	if d <= 0 {
		return
	}
	if c.ended.Load() {
		return
	}
	t := time.AfterFunc(d, func() {
		if !c.authed.Load() {
			c.nc.Close()
		}
	})
	if old := c.preTimer.Swap(t); old != nil {
		old.Stop()
	}
	if c.ended.Load() {
		t.Stop()
	}
}

// stopClocks ends both clocks for good: the connection is over. A timer holds the
// connection it closes over, and the idle one re-arms itself for as long as a
// handle is open, so one left running after a client dropped with a file open
// would keep the connection -- its tables and buffers -- alive for ever.
func (c *conn) stopClocks() {
	c.ended.Store(true)
	if t := c.preTimer.Swap(nil); t != nil {
		t.Stop()
	}
	if t := c.idleTimer.Swap(nil); t != nil {
		t.Stop()
	}
}

// touch records that the client has just done something.
func (c *conn) touch() { c.lastActive.Store(time.Now().UnixNano()) }

func (c *conn) armIdle(d time.Duration) {
	if c.ended.Load() {
		return
	}
	t := time.AfterFunc(d, c.idleCheck)
	if old := c.idleTimer.Swap(t); old != nil {
		old.Stop()
	}
	if c.ended.Load() { // the connection ended while this was being armed
		t.Stop()
	}
}

// idleCheck closes an authenticated connection that has said nothing for the idle
// timeout and has nothing the client could be waiting on: no open handle, no
// operation pending (a change notification is a request that is meant to wait). A
// connection that is not idle is looked at again when it could be.
func (c *conn) idleCheck() {
	limit := c.srv.idleTimeout()
	if limit <= 0 || !c.authed.Load() || c.ended.Load() {
		return
	}
	idle := time.Since(time.Unix(0, c.lastActive.Load()))
	if idle >= limit {
		c.mu.Lock()
		waiting := len(c.waiting)
		c.mu.Unlock()
		if c.nOpen.Load() <= 0 && waiting == 0 {
			c.nc.Close()
			return
		}
		idle = 0 // busy with something that is not a request: ask again in a full period
	}
	c.armIdle(limit - idle)
}

type connLimitState struct {
	authed     atomic.Bool
	counted    atomic.Bool
	preTimer   atomic.Pointer[time.Timer]
	idleTimer  atomic.Pointer[time.Timer]
	lastActive atomic.Int64 // UnixNano of the last frame
	nOpen      atomic.Int64 // open handles, files and pipes
	ended      atomic.Bool  // serve has returned: no clock may be armed
}
