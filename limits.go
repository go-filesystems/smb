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

func (s *Server) maxConnections() int { return resolveLimit(s.MaxConnections, DefaultMaxConnections) }
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
	if t := c.preTimer.Load(); t != nil {
		t.Stop()
	}
	if c.counted.CompareAndSwap(true, false) {
		c.srv.mu.Lock()
		c.srv.preAuth--
		c.srv.mu.Unlock()
	}
}

// startPreAuthClock closes the connection if nobody has authenticated on it in
// time.
func (c *conn) startPreAuthClock() {
	d := c.srv.preAuthTimeout()
	if d <= 0 {
		return
	}
	t := time.AfterFunc(d, func() {
		if !c.authed.Load() {
			c.nc.Close()
		}
	})
	c.preTimer.Store(t)
}

type connLimitState struct {
	authed   atomic.Bool
	counted  atomic.Bool
	preTimer atomic.Pointer[time.Timer]
}
