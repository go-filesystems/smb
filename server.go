// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	filesystem "github.com/go-filesystems/interface"
)

// A Server exports one or more shares over SMB2.
//
//	fs, err := fat32.Open("disk.img", -1)
//	…
//	srv := smb.New()
//	srv.AddUser("alice", "secret")
//	if err := srv.Share("disk", fs); err != nil {
//		return err
//	}
//	return srv.ListenAndServe("127.0.0.1:4445")
//
// Port 445 is the one clients dial without being told; it needs privilege on
// every OS, so the examples use a high port and the mount command names it.
type Server struct {
	mu     sync.Mutex
	shares map[string]*share
	users  map[string]string // user name (as sent) -> password
	name   string
	lns    []net.Listener
	conns  map[*conn]struct{}
	closed bool
}

type share struct {
	name string
	fsys filesystem.Filesystem
	ro   bool
}

// ShareOption changes how one share is exported.
type ShareOption func(*share)

// ReadOnly refuses every write on this share, whatever the driver underneath
// would have allowed.
func ReadOnly() ShareOption { return func(s *share) { s.ro = true } }

// New returns a server with no shares and no users. A server with no users
// authenticates nobody: SMB has no anonymous mode worth offering, and a client
// asked to mount without credentials is told so rather than let in.
func New() *Server {
	return &Server{
		shares: map[string]*share{},
		users:  map[string]string{},
		name:   "GOFS",
		conns:  map[*conn]struct{}{},
	}
}

// SetName sets the NetBIOS-style name the server calls itself in the NTLM
// challenge. It is cosmetic -- clients show it -- but it must be stable across
// the two halves of an authentication, which is why it is a field and not a
// per-message decision.
func (s *Server) SetName(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.name = name
}

// AddUser adds a set of credentials the server will accept.
func (s *Server) AddUser(user, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user] = password
}

// Share exports a filesystem under a name. The name is what appears after the
// host in \\host\name, and SMB compares it without case.
func (s *Server) Share(name string, fsys filesystem.Filesystem, opts ...ShareOption) error {
	if name == "" {
		return errors.New("smb: a share needs a name")
	}
	if strings.ContainsAny(name, `\/`) {
		return fmt.Errorf("smb: %q is not a share name: it has a path separator in it", name)
	}
	if fsys == nil {
		return errors.New("smb: a share needs a filesystem")
	}
	sh := &share{name: name, fsys: fsys}
	for _, o := range opts {
		o(sh)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.shares[strings.ToUpper(name)]; taken {
		return fmt.Errorf("smb: there is already a share called %q", name)
	}
	s.shares[strings.ToUpper(name)] = sh
	return nil
}

func (s *Server) shareByName(name string) *share {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shares[strings.ToUpper(name)]
}

func (s *Server) password(user string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.users[user]
	return p, ok
}

func (s *Server) serverName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.name
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.lns = append(s.lns, ln)
	s.mu.Unlock()
	for {
		nc, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		c := &conn{srv: s, nc: nc, sessions: map[uint64]*session{}, trees: map[uint32]*share{}}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		go func() {
			c.serve()
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
		}()
	}
}

// ListenAndServe listens on addr and serves until Close.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Close stops the listeners and drops every connection.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	lns, conns := s.lns, s.conns
	s.lns, s.conns = nil, map[*conn]struct{}{}
	s.mu.Unlock()
	var err error
	for _, ln := range lns {
		if e := ln.Close(); e != nil && err == nil {
			err = e
		}
	}
	for c := range conns {
		c.nc.Close()
	}
	return err
}

// A conn is one client, and everything it has opened.
type conn struct {
	srv *Server
	nc  net.Conn

	dialect  uint16
	nextID   uint64
	sessions map[uint64]*session
	trees    map[uint32]*share
	nextTree uint32
	pending  *challenge // the NTLM challenge sent, awaiting its answer
}

// A session is one authenticated user on one connection.
type session struct {
	user       string
	sessionKey []byte
}

func (c *conn) serve() {
	defer c.nc.Close()
	for {
		msg, err := readFrame(c.nc)
		if err != nil {
			return
		}
		out, err := c.dispatch(msg)
		if err != nil {
			return
		}
		if out == nil {
			continue
		}
		if err := writeFrame(c.nc, out); err != nil {
			return
		}
	}
}

// dispatch answers one message. An error stops the connection; a nil response
// means there is nothing to send back.
func (c *conn) dispatch(msg []byte) ([]byte, error) {
	// The legacy greeting is the one SMB1 message this server reads, and the
	// only answer it gives is an SMB2 negotiate response naming the wildcard
	// dialect: "ask me again in SMB2".
	if len(msg) >= 4 && [4]byte(msg[:4]) == smb1ProtocolID {
		return c.legacyNegotiateResponse()
	}
	h, err := parseHeader(msg)
	if err != nil {
		return nil, err
	}
	body := msg[headerLen:]
	switch h.command {
	case cmdNegotiate:
		return c.negotiate(h, body)
	case cmdSessionSetup:
		return c.sessionSetup(h, body)
	case cmdLogoff:
		delete(c.sessions, h.sessionID)
		return simpleResponse(h, statusSuccess, 4), nil
	case cmdTreeConnect:
		return c.treeConnect(h, body, msg)
	case cmdTreeDisconnect:
		delete(c.trees, h.treeID)
		return simpleResponse(h, statusSuccess, 4), nil
	case cmdEcho:
		return simpleResponse(h, statusSuccess, 4), nil
	default:
		// Everything else is the next tranche. Refusing by name is what lets a
		// client fall back or report, instead of waiting for a reply that
		// never comes.
		return errorResponse(h, statusNotImplemented), nil
	}
}

// simpleResponse builds a reply whose body is just a structure size.
func simpleResponse(h header, status uint32, structSize uint16) []byte {
	b := append(responseTo(h, status), make([]byte, 4)...)
	binary.LittleEndian.PutUint16(b[headerLen:], structSize)
	return b
}

// errorResponse is the shape a client expects for a failure: a nine-byte body
// whose structure size is 9 and whose byte count is zero.
func errorResponse(h header, status uint32) []byte {
	b := append(responseTo(h, status), make([]byte, 9)...)
	binary.LittleEndian.PutUint16(b[headerLen:], 9)
	return b
}
