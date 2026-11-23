// SPDX-License-Identifier: BSD-3-Clause

//go:build !noquic

package smb

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// SMB 3.1.1 over QUIC ([MS-SMB2] 2.1, "SMB2 dialect 3.1.1 allows operation over
// QUIC transport [RFC9000]"). The byte stream of one QUIC connection is the
// Direct TCP stream, unchanged (4-byte header, then the message), on the first
// client-initiated bidirectional stream; so the transport is an adapter that
// turns each QUIC connection into one net.Conn, and Serve does the rest.
//
// Bibliography (opened 2026-11-23): [MS-SMB2] 2.1, 3.3.5.4; IANA ALPN registry
// (SMB2 = "smb"); RFC 9000 8.1 (amplification), 8.1.2 (Retry), 21.2-21.9 (DoS);
// quic-go v0.64.1 interface.go (Config), transport.go (VerifySourceAddress).

// quicALPN is the TLS application protocol of SMB over QUIC.
const quicALPN = "smb"

// Defaults of the bounds. Memory per connection is bounded by the windows; the
// handshake and the first stream are bounded in time.
const (
	defaultQUICStreamWindow = 16 << 20
	defaultQUICConnWindow   = 16 << 20
	defaultQUICMaxConns     = 1024
	defaultQUICRetryRate    = 64 // Initial packets per second from unvalidated sources before Retry
	quicCloseGrace          = 100 * time.Millisecond
)

// quicHandshakeTimeout bounds the TLS handshake. A variable so a test run
// under CPU emulation (s390x under qemu-user) can lengthen it.
var quicHandshakeTimeout = 5 * time.Second

// quicStreamWait is how long a connection that completed its handshake may
// take to open its first stream. Atomic so a test can shorten it while a
// connection of an earlier test is still reading it.
var quicStreamWait = func() *atomic.Int64 {
	v := new(atomic.Int64)
	v.Store(int64(10 * time.Second))
	return v
}()

type quicOptions struct {
	streamWin, connWin uint64
	maxConns           int
	retryRate          int
}

// A QUICOption adjusts [ListenQUIC].
type QUICOption func(*quicOptions)

// WithQUICWindows sets the largest flow-control windows, per stream and per
// connection, which bound what one peer that never reads can make the server
// buffer. Zero keeps the default (16 MiB each).
func WithQUICWindows(stream, conn uint64) QUICOption {
	return func(o *quicOptions) {
		if stream > 0 {
			o.streamWin = stream
		}
		if conn > 0 {
			o.connWin = conn
		}
	}
}

// WithQUICMaxConnections bounds the QUIC connections the listener holds, both
// the ones waiting for their first stream and the ones accepted and not yet
// closed. Above it a new connection is closed with an application error.
func WithQUICMaxConnections(n int) QUICOption {
	return func(o *quicOptions) {
		if n > 0 {
			o.maxConns = n
		}
	}
}

// WithQUICRetryRate sets how many Initial packets per second from addresses not
// yet validated the listener tolerates before it answers with a Retry (RFC 9000
// 8.1.2), which costs the client one round trip and the server no state. Under
// that rate no round trip is added.
func WithQUICRetryRate(perSecond int) QUICOption {
	return func(o *quicOptions) {
		if perSecond > 0 {
			o.retryRate = perSecond
		}
	}
}

// quicListen is quic-go's Transport.Listen, a variable so a test can make it
// fail: it cannot on a valid configuration, and the cleanup after it must run.
var quicListen = func(tr *quic.Transport, c *tls.Config, qc *quic.Config) (*quic.Listener, error) {
	return tr.Listen(c, qc)
}

// ListenQUIC listens on UDP addr and returns a net.Listener whose Accept yields
// one net.Conn per QUIC connection: its first bidirectional stream, with
// RemoteAddr the client's UDP address. Pass it to [Server.Serve].
//
// tlsConf must carry the server certificate. The listener forces TLS 1.3 and
// the ALPN "smb", never accepts 0-RTT, lets a peer open one bidirectional
// stream and no unidirectional one, and sends Retry when Initials arrive faster
// than [WithQUICRetryRate]. Set ClientAuth and ClientCAs on tlsConf to require
// a client certificate (see [RequireClientCertificate]).
func ListenQUIC(addr string, tlsConf *tls.Config, opts ...QUICOption) (net.Listener, error) {
	if tlsConf == nil {
		return nil, errors.New("smb: ListenQUIC needs a tls.Config")
	}
	o := quicOptions{streamWin: defaultQUICStreamWindow, connWin: defaultQUICConnWindow,
		maxConns: defaultQUICMaxConns, retryRate: defaultQUICRetryRate}
	for _, f := range opts {
		f(&o)
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	conf := tlsConf.Clone()
	conf.MinVersion = tls.VersionTLS13
	conf.NextProtos = []string{quicALPN}
	l := &quicListener{
		pc: pc, max: o.maxConns, out: make(chan net.Conn), done: make(chan struct{}),
		slots: make(chan struct{}, o.maxConns),
	}
	l.rate = o.retryRate
	l.tr = &quic.Transport{Conn: pc, VerifySourceAddress: l.verify}
	ql, err := quicListen(l.tr, conf, &quic.Config{
		HandshakeIdleTimeout:           quicHandshakeTimeout,
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                20 * time.Second,
		MaxIncomingStreams:             1,
		MaxIncomingUniStreams:          -1,
		InitialStreamReceiveWindow:     min(o.streamWin, 512<<10),
		MaxStreamReceiveWindow:         o.streamWin,
		InitialConnectionReceiveWindow: min(o.connWin, 512<<10),
		MaxConnectionReceiveWindow:     o.connWin,
		Allow0RTT:                      false,
	})
	if err != nil {
		pc.Close()
		return nil, err
	}
	l.ql = ql
	go l.acceptLoop()
	return l, nil
}

type quicListener struct {
	pc    net.PacketConn
	tr    *quic.Transport
	ql    *quic.Listener
	max   int
	slots chan struct{} // one token per live connection
	out   chan net.Conn
	done  chan struct{}
	once  sync.Once

	rate    int
	mu      sync.Mutex
	winFrom time.Time
	winN    int
	retries atomic.Uint64
}

// verify is quic-go's VerifySourceAddress: true asks for a Retry. It is called
// for each Initial from an unvalidated address, so counting the calls in a
// one-second window measures the handshakes arriving.
func (l *quicListener) verify(net.Addr) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.winFrom) >= time.Second {
		l.winFrom, l.winN = now, 0
	}
	l.winN++
	if l.winN > l.rate {
		l.retries.Add(1)
		return true
	}
	return false
}

func (l *quicListener) acceptLoop() {
	for {
		qc, err := l.ql.Accept(context.Background())
		if err != nil {
			return // closed
		}
		select {
		case l.slots <- struct{}{}:
		default:
			qc.CloseWithError(quicErrBusy, "too many connections")
			continue
		}
		go l.firstStream(qc)
	}
}

// Application error codes: what a peer sees in the CONNECTION_CLOSE.
const (
	quicErrOK     quic.ApplicationErrorCode = 0
	quicErrBusy   quic.ApplicationErrorCode = 1
	quicErrNoStrm quic.ApplicationErrorCode = 2
)

// firstStream waits, for a bounded time, for the one stream SMB uses, then hands
// the connection to Accept. A client that completes the handshake and never
// opens it holds a slot for quicStreamWait and no more.
func (l *quicListener) firstStream(qc *quic.Conn) {
	release := func() { <-l.slots }
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(quicStreamWait.Load()))
	defer cancel()
	st, err := qc.AcceptStream(ctx)
	if err != nil {
		qc.CloseWithError(quicErrNoStrm, "no stream")
		release()
		return
	}
	c := &quicConn{qc: qc, st: st, release: release}
	select {
	case l.out <- c:
	case <-l.done:
		c.Close()
	}
}

func (l *quicListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.out:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *quicListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.ql.Close()
		if e := l.tr.Close(); e != nil && err == nil {
			err = e
		}
		l.pc.Close()
	})
	return err
}

func (l *quicListener) Addr() net.Addr { return l.pc.LocalAddr() }

// A quicConn is the stream of one QUIC connection, as a net.Conn.
type quicConn struct {
	qc      *quic.Conn
	st      *quic.Stream
	release func()
	once    sync.Once
}

// TransportName is Connection.TransportName ([MS-SMB2] 3.3.1.7).
func (c *quicConn) TransportName() string { return "quic" }

func (c *quicConn) Read(p []byte) (int, error)         { return c.st.Read(p) }
func (c *quicConn) Write(p []byte) (int, error)        { return c.st.Write(p) }
func (c *quicConn) LocalAddr() net.Addr                { return c.qc.LocalAddr() }
func (c *quicConn) RemoteAddr() net.Addr               { return c.qc.RemoteAddr() }
func (c *quicConn) SetDeadline(t time.Time) error      { return c.st.SetDeadline(t) }
func (c *quicConn) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *quicConn) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }

// ConnectionState is the TLS state of the connection (peer certificates, ALPN).
func (c *quicConn) ConnectionState() tls.ConnectionState {
	return c.qc.ConnectionState().TLS
}

// Close ends the stream and the QUIC connection. The stream's FIN and what is
// still queued get a short grace before the CONNECTION_CLOSE, which would
// otherwise drop them; the connection's slot is returned at once.
func (c *quicConn) Close() error {
	c.once.Do(func() {
		c.st.CancelRead(0)
		c.st.Close()
		c.release()
		time.AfterFunc(quicCloseGrace, func() { c.qc.CloseWithError(quicErrOK, "") })
	})
	return nil
}
