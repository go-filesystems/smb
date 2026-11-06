// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/go-filesystems/inflight"
)

// Concurrent requests.
//
// Bibliography (opened 2026-11-06), MS-SMB2:
//
//   - Algorithm for Handling Available Message Sequence Numbers by the Server
//     (3.3.1.1): the server must accept requests that arrive out of order, and
//     the credits it has granted are what bounds the window.
//   - Algorithm for the Granting of Credits (3.3.1.2) and Granting Credits to
//     the Client (3.3.4.1.2): a reply carries CreditResponse, and a client
//     matches a reply to its request by MessageId, not by position.
//   - Handling Compounded Requests (3.3.5.2.7) and Handling Compounded Related
//     Requests: "The server MUST handle each individual operation that is
//     described in the chain in order", taking FileId, SessionId and TreeId
//     from the previous operation; an operation that needs asynchronous
//     processing gets an interim response (3.3.4.2).
//
// What follows from them:
//
//   - One FRAME is one unit. A frame holding a compound chain is answered whole,
//     in order, as it was before, and runs as a barrier.
//   - A frame holding one READ of a plain file runs beside others: that is the
//     request a transfer is made of, and the share lock already lets readers
//     share (see share.mu). Replies leave as they are ready, each carrying its
//     own MessageId.
//   - Every other request is a barrier: it waits for everything in flight and
//     runs alone, so the per-connection tables (sessions, trees, files, search
//     cursors) are only ever written when nothing else touches them. That
//     includes the requests that become asynchronous (lock waits, CHANGE_NOTIFY):
//     their interim reply is sent by the barrier and the final one by the
//     goroutine async.go already starts.
//   - WRITE stays a barrier: it holds the share lock exclusively for the whole
//     command, so running it beside anything would gain nothing.
//
// The bound is the number of requests in progress, MaxInFlight per connection
// and MaxInFlightTotal over the server, both taken before a frame is read. The
// credits the server grants (creditsFor) are the protocol's own window and are
// unchanged: a client that has been granted more credits than the server will
// work on at once simply waits in the transport, like any other client of a
// busy server.

// Defaults for [Server.MaxInFlight] and [Server.MaxInFlightTotal].
const (
	// DefaultMaxInFlight is how many requests one connection has in progress
	// at once. macOS and Windows keep a few dozen reads outstanding.
	DefaultMaxInFlight = 32
	// DefaultMaxInFlightTotal bounds the requests in progress across every
	// connection: each READ holds up to maxReadSize (1 MiB) of reply, so memory
	// for them is at most about 128 MiB.
	DefaultMaxInFlightTotal = 128
)

var errPanic = errors.New("smb: panic answering a request")

// inflightPool returns the server-wide budget, made on first use so the fields
// can be set any time before the first connection.
func (s *Server) inflightPool() *inflight.Pool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pool == nil {
		n := s.MaxInFlightTotal
		if n <= 0 {
			n = DefaultMaxInFlightTotal
		}
		s.pool, _ = inflight.NewPool(n) // n is at least 1
	}
	return s.pool
}

// maxInFlight resolves [Server.MaxInFlight]: zero is the default, a negative
// value is 1 (one request at a time, as before v0.8).
func (s *Server) maxInFlight() int {
	switch {
	case s.MaxInFlight == 0:
		return DefaultMaxInFlight
	case s.MaxInFlight < 0:
		return 1
	}
	return s.MaxInFlight
}

// frameSender writes one reply frame, serialised with the frames async.go
// sends from other goroutines. A failed write closes the connection, which is
// what wakes the reader that is waiting for the next frame.
type frameSender struct{ c *conn }

func (f frameSender) Write(p []byte) (int, error) {
	err := f.c.send(p)
	if err != nil {
		f.c.nc.Close()
	}
	return len(p), err
}

// readSpan says whether msg is one READ of a plain file (not a pipe, not a
// directory) that may run beside others, and what it touches.
func (c *conn) readSpan(msg []byte) (inflight.Span, bool) {
	if len(msg) < headerLen+48 {
		return inflight.Span{}, false
	}
	h, err := parseHeader(msg)
	if err != nil || h.command != cmdRead || h.nextCommand != 0 {
		return inflight.Span{}, false
	}
	body := msg[headerLen:]
	of := c.fileByID(body[16:])
	if of == nil || of.pipe != nil || of.dir {
		return inflight.Span{}, false
	}
	length := uint64(binary.LittleEndian.Uint32(body[4:]))
	offset := binary.LittleEndian.Uint64(body[8:])
	return inflight.ReadRange(string(body[16:32]), offset, length), true
}

// runner is the work of one frame as inflight runs it. A panic in it (the
// driver underneath parses an image this server did not write) ends the
// connection and is recorded, as serve has always done, and not the process.
func (c *conn) runner(msg []byte) inflight.Run {
	return func(*inflight.Slot) (out []byte, err error) {
		defer func() {
			if r := recover(); r != nil {
				c.mu.Lock()
				c.panicked = r
				c.mu.Unlock()
				out, err = nil, errPanic
			}
		}()
		return c.dispatchChain(msg)
	}
}

// prefixed hands out one byte already taken from r first.
type prefixed struct {
	r    io.Reader
	b    byte
	have bool
}

func (p *prefixed) reset(r io.Reader, b byte) { p.r, p.b, p.have = r, b, true }

func (p *prefixed) Read(b []byte) (int, error) {
	if p.have && len(b) > 0 {
		b[0], p.have = p.b, false
		return 1, nil
	}
	return p.r.Read(b)
}
