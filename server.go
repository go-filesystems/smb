// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"crypto/rand"
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
	guid   [16]byte
	lns    []net.Listener
	conns  map[*conn]struct{}
	closed bool
}

type share struct {
	name string
	fsys filesystem.Filesystem
	ro   bool

	// locks are the byte ranges applications have reserved on this share.
	// They belong to the share rather than to a connection because that is
	// the whole point of them: they are how two clients keep out of each
	// other's way.
	locks lockTable

	// mu serialises the driver.
	//
	// A Filesystem promises NOTHING about concurrent path-based calls --
	// only File.ReadAt and non-overlapping File.WriteAt are documented as
	// safe -- and this server hands one Filesystem to every connection at
	// once. macOS opens two connections for a single mount, so it is not a
	// question of several people: one person is enough.
	//
	// It is held for the whole of a command rather than around each call,
	// because the commands are not single calls. CREATE stats, may write,
	// stats again and opens: two clients creating the same file would
	// otherwise both find it missing and both create it.
	//
	// Reads share it. A mount is mostly reading, and excluding readers from
	// each other would make one slow file block a whole share.
	mu sync.RWMutex
	// ipc marks the pipe share a client connects to before it will use a real
	// one. It has no filesystem behind it, and every file operation on it is
	// refused rather than followed into a nil.
	ipc bool
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
	s := &Server{
		shares: map[string]*share{},
		users:  map[string]string{},
		name:   "GOFS",
		conns:  map[*conn]struct{}{},
	}
	// One identity for the life of the server: a client that validates the
	// negotiate exchange compares this against what it was told, and a fresh
	// one per connection would look like an attack.
	rand.Read(s.guid[:])
	return s
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

// reading takes the share's lock for a command that only reads, and returns
// the release: `defer sh.reading()()`.
func (s *share) reading() func() {
	s.mu.RLock()
	return s.mu.RUnlock
}

// changing takes it for a command that may write.
func (s *share) changing() func() {
	s.mu.Lock()
	return s.mu.Unlock
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
		c := newConn(s, nc)
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

	dialect            uint16
	clientSecurityMode uint16
	clientCapabilities uint32
	nextID             uint64
	sessions           map[uint64]*session
	trees              map[uint32]*share
	nextTree           uint32
	pending            *challenge // the NTLM challenge sent, awaiting its answer
	spnego             bool       // whether this client wraps its tokens, or sends them bare

	panicked any // what a connection died of, for a test to insist on
	files    map[[16]byte]*openFile
	nextFile uint64
	lastFile [16]byte // what an all-ones file id in a chained request means
	// searches remembers where a directory listing got to, keyed by the
	// handle it is being read through: SMB asks for a directory in pages and
	// expects the second page to continue the first.
	searches map[[16]byte]*search
}

func newConn(s *Server, nc net.Conn) *conn {
	return &conn{
		srv: s, nc: nc,
		sessions: map[uint64]*session{},
		trees:    map[uint32]*share{},
		files:    map[[16]byte]*openFile{},
		searches: map[[16]byte]*search{},
	}
}

// A session is one authenticated user on one connection.
type session struct {
	user       string
	sessionKey []byte
	signingKey []byte
}

func (c *conn) serve() {
	defer c.nc.Close()
	// One connection's crash must not be every connection's. A panic here is
	// a defect and will be fixed, but a server that dies of one takes every
	// other client's mount with it -- and the driver underneath is parsing an
	// image this server did not write.
	defer func() {
		if r := recover(); r != nil {
			c.panicked = r
		}
	}()
	// A client that hangs up mid-transfer still holds driver handles; they are
	// the driver's memory, not ours, and nothing else will close them.
	defer func() {
		for _, of := range c.files {
			if of.f != nil {
				of.f.Close()
			}
			// A client that crashes holding a lock must not keep the file
			// reserved for the life of the server.
			of.share.locks.releaseAll(of.id)
		}
	}()
	for {
		msg, err := readFrame(c.nc)
		if err != nil {
			return
		}
		out, err := c.dispatchChain(msg)
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

// dispatchChain answers one FRAME, which may hold several requests.
//
// A client is allowed to chain requests -- NextCommand in each header says
// where the next one starts -- and macOS does it on every open: CREATE,
// QUERY_INFO and CLOSE arrive in a single message. A server that answers only
// the first leaves the client waiting for replies that never come, which is
// exactly what a mount attempt looked like before this existed: the handshake
// went through, one CREATE was answered, and the client sat there until it
// timed out.
//
// The replies are chained the same way. Each one but the last is padded to an
// eight-byte boundary, because the offset that points at its successor has to
// land on one.
func (c *conn) dispatchChain(msg []byte) ([]byte, error) {
	// The legacy greeting is not an SMB2 message and has no header to parse,
	// so it is answered before the loop that reads one. Putting this check
	// only inside dispatch is a mistake that costs a whole afternoon: the Go
	// client never sends the greeting, so the tests stay green while every
	// mount from macOS dies at the first frame, silently.
	if len(msg) >= 4 && [4]byte(msg[:4]) == smb1ProtocolID {
		return c.legacyNegotiateResponse()
	}
	var (
		out       []byte
		prevAt    = -1 // where the previous reply's header starts, inside out
		first     header
		haveFirst bool
	)
	for {
		h, err := parseHeader(msg)
		if err != nil {
			return nil, err
		}
		end := len(msg)
		if h.nextCommand != 0 {
			if int(h.nextCommand) > len(msg) || h.nextCommand < headerLen {
				return nil, fmt.Errorf("smb: a chained request says the next one starts at %d of %d bytes", h.nextCommand, len(msg))
			}
			end = int(h.nextCommand)
		}
		one := msg[:end]
		// The related-operations flag means this request speaks about what the
		// first one opened: it carries no session or tree of its own.
		if haveFirst && h.flags&flagRelatedOps != 0 {
			one = withInheritedIDs(one, first)
		}
		if !haveFirst {
			first, haveFirst = h, true
		}

		// A signed request is verified before it is read. A signature that
		// does not check out is not a request from the party that
		// authenticated, whatever it says in its header.
		sess := c.sessions[binary.LittleEndian.Uint64(one[offSessionID:])]
		if h.flags&flagSigned != 0 {
			if sess == nil || !verifyMessage(c.dialect, sess.signingKey, one) {
				return c.finish(out, prevAt, errorResponse(h, statusAccessDenied), sess, h), nil
			}
		}

		reply, err := c.dispatch(one)
		if err != nil {
			return nil, err
		}
		// Signed in kind: a client that signed its request checks the reply,
		// and one that did not would reject a signature it cannot verify.
		if reply != nil && h.flags&flagSigned != 0 && sess != nil {
			signMessage(c.dialect, sess.signingKey, reply)
		}
		if reply != nil {
			if prevAt >= 0 {
				binary.LittleEndian.PutUint32(out[prevAt+offNextCommand:], uint32(len(out)-prevAt))
			}
			prevAt = len(out)
			out = append(out, reply...)
			if h.nextCommand != 0 {
				for len(out)%8 != 0 {
					out = append(out, 0)
				}
			}
		}
		if h.nextCommand == 0 {
			return out, nil
		}
		msg = msg[end:]
	}
}

// finish appends one last reply to a chain and returns what to send. The
// refusal path uses it so a rejected signature still answers in the shape the
// client is reading.
func (c *conn) finish(out []byte, prevAt int, reply []byte, sess *session, h header) []byte {
	if sess != nil && h.flags&flagSigned != 0 {
		signMessage(c.dialect, sess.signingKey, reply)
	}
	if prevAt >= 0 {
		binary.LittleEndian.PutUint32(out[prevAt+offNextCommand:], uint32(len(out)-prevAt))
	}
	return append(out, reply...)
}

// withInheritedIDs gives a chained request the session and tree of the one it
// follows, which is what the related-operations flag means. The handle is
// inherited too, but that is spelled inside the body -- an all-ones file id --
// and is resolved where the handles live.
func withInheritedIDs(msg []byte, first header) []byte {
	out := append([]byte(nil), msg...)
	binary.LittleEndian.PutUint32(out[offTreeID:], first.treeID)
	binary.LittleEndian.PutUint64(out[offSessionID:], first.sessionID)
	return out
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
	case cmdCreate:
		return c.create(h, body, msg)
	case cmdClose:
		return c.closeFile(h, body)
	case cmdRead:
		return c.read(h, body)
	case cmdWrite:
		return c.write(h, body, msg)
	case cmdFlush:
		return c.flush(h, body)
	case cmdQueryDirectory:
		return c.queryDirectory(h, body, msg)
	case cmdQueryInfo:
		return c.queryInfo(h, body)
	case cmdSetInfo:
		return c.setInfo(h, body, msg)
	case cmdIoctl:
		return c.ioctl(h, body, msg)
	case cmdLock:
		return c.lock(h, body)
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
