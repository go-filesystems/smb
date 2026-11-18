// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-filesystems/inflight"
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
	users  map[string]credential // user name (as sent) -> what proves them
	name   string
	guid   [16]byte
	lns    []net.Listener
	conns  map[*conn]struct{}
	closed bool

	// MaxInFlight is how many requests one connection may have in progress at
	// once. Zero means [DefaultMaxInFlight]; a negative value means 1, the
	// one-request-at-a-time server of v0.7 and before. Set it before the first
	// connection.
	MaxInFlight int
	// Kerberos, when set, makes the server accept Kerberos in SPNEGO: it offers
	// MS-KRB5 and Kerberos V5 ahead of NTLMSSP, and hands the AP-REQ to the
	// acceptor. See [Acceptor]. Set it before the first connection.
	Kerberos Acceptor
	// DisableNTLM refuses NTLMSSP: the NEGOTIATE response does not offer it and a
	// client that sends it anyway is answered STATUS_LOGON_FAILURE. It needs
	// [Server.Kerberos], and [Server.Serve] returns [ErrNeedKerberos] without it.
	// The users added with [Server.AddUser] have no use then, since a password is
	// only ever checked by NTLM. Set it before the first connection.
	DisableNTLM bool
	// Logger receives the [TimesLog] lines. Nil means slog.Default(). (The
	// server had no logger before; this is its first.) Set it before the first
	// connection.
	Logger *slog.Logger
	// MaxInFlightTotal caps the requests in progress across every connection.
	// Zero or less means [DefaultMaxInFlightTotal]. A request takes its share
	// before its frame is read and gives it back when its reply is written, so
	// a client that does not read its replies keeps its requests counted.
	// Set it before the first connection.
	MaxInFlightTotal int
	// RecordTimeout bounds how long the rest of a frame may take once its
	// first byte has arrived: the request holds a slot and a token of the
	// budget meanwhile. Zero means [DefaultRecordTimeout]; a negative value
	// disables it. A frame that does not complete in time closes the
	// connection. Set it before the first connection.
	RecordTimeout time.Duration
	pool          *inflight.Pool // made by the first connection

	// EncryptData requires encryption of every session: a client that cannot
	// encrypt (SMB 2.1, or 3.x with no cipher in common) is refused at
	// SESSION_SETUP with STATUS_ACCESS_DENIED, and one that can is told to
	// (SMB2_SESSION_FLAG_ENCRYPT_DATA) and has any unencrypted request refused.
	// To require it of one share only, use [RequireEncryption]. Set it before
	// the first connection.
	EncryptData bool
	// RequireSigning makes the server require message signing of every client
	// ([MS-SMB2] 3.3.5.4: SMB2_NEGOTIATE_SIGNING_REQUIRED in the NEGOTIATE
	// response): every session is held to it, so a request that arrives neither
	// signed nor encrypted is refused with STATUS_ACCESS_DENIED whether or not
	// the client asked for signing. Windows clients require it already; this is
	// what makes the server the one that insists. Set it before the first
	// connection.
	RequireSigning bool
	// DisableEncryption stops the server offering encryption at all: no
	// ENCRYPTION context is answered on 3.1.1 and the capability is not claimed
	// on 3.0 and 3.0.2. It outranks [Server.EncryptData] and [RequireEncryption],
	// whose shares then refuse every connection. Set it before the first
	// connection.
	DisableEncryption bool
	// MaxConnections is how many connections the server holds at once; zero means
	// [DefaultMaxConnections] and a negative value no limit. A connection over the
	// limit is closed as it is accepted. Set it before the first connection.
	//
	// Every connection is a file descriptor, and so is every file a driver opens:
	// where the process's soft descriptor limit (RLIMIT_NOFILE) is below the
	// default, the default is three quarters of it (192 on macOS, whose limit is
	// 256) so that EMFILE is not what reaches first; raise the limit and set this
	// to use more.
	MaxConnections int
	// MaxPreAuthConnections is how many connections may have no authenticated
	// session; zero means [DefaultMaxPreAuthConnections], a negative value no
	// limit. A flood of connections that never log in fills this and nothing more,
	// and a client that does log in frees its place. Set it before the first
	// connection.
	MaxPreAuthConnections int
	// PreAuthTimeout is how long a connection may go without authenticating before
	// it is closed; zero means [DefaultPreAuthTimeout], a negative value never.
	// Set it before the first connection.
	PreAuthTimeout time.Duration
	// MaxConnectionsPerSource and MaxPreAuthPerSource bound what one remote
	// address (an IPv6 address by its /64) may hold, in all and with no
	// authenticated session; zero means [DefaultMaxConnectionsPerSource] (32) and
	// [DefaultMaxPreAuthPerSource] (16), a negative value no limit. One source
	// flooding cannot lock out another. Raise them behind a NAT or a proxy, where
	// many clients share an address. Loopback is not exempt. Set before the first
	// connection.
	MaxConnectionsPerSource int
	MaxPreAuthPerSource     int
	srcTotal, srcPre        map[string]int // guarded by mu
	// IdleTimeout is how long an authenticated connection with no open handle and
	// no operation pending may go without a request before it is closed; zero
	// means [DefaultIdleTimeout], a negative value never. A connection whose last
	// session logs off counts as unauthenticated again. Set it before the first
	// connection.
	IdleTimeout time.Duration

	// preAuth counts the connections with no authenticated session; dropped is how
	// many the limits have refused, and dropping is whether the log has already
	// said so for the current burst. Guarded by mu.
	preAuth  int
	dropped  int
	dropping bool
	closing  chan struct{} // closed by Close
}

type share struct {
	name string
	fsys filesystem.Filesystem
	ro   bool
	// allow and writers are who may connect and who may write. See access.go:
	// empty means everyone who authenticated.
	allow   []string
	writers []string
	// decide, when set, answers instead of allow and writers. See Access.
	decide func(user string) (connect, write bool)
	// capacity is what the size information classes report, or nil for the
	// placeholder. See WithCapacity and WithCapacityFunc.
	capacity func() (total, avail uint64)
	// timePolicy is what happens to a time a client sets and the server cannot
	// store. See [TimePolicy]; the zero value is the default, [TimesIgnore].
	timePolicy TimePolicy
	// encrypt is [RequireEncryption]: every request on this share must arrive
	// encrypted, and the TREE_CONNECT response says so.
	encrypt bool

	// locks are the byte ranges applications have reserved on this share.
	// They belong to the share rather than to a connection because that is
	// the whole point of them: they are how two clients keep out of each
	// other's way.
	locks lockTable

	// watchers are the outstanding CHANGE_NOTIFY requests on this share. See
	// notify.go for what they can and cannot see.
	watchers watchers

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

// RequireEncryption makes this share refuse everything that is not encrypted
// ([MS-SMB2] 3.3.5.2.11, with Share.EncryptData and RejectUnencryptedAccess
// both TRUE). TREE_CONNECT answers SMB2_SHAREFLAG_ENCRYPT_DATA, so a client
// encrypts from then on; a request on the share that arrives unencrypted is
// answered STATUS_ACCESS_DENIED, and everything the server sends on it is
// encrypted. A client that cannot encrypt -- SMB 2.1, or 3.x with no cipher in
// common -- is refused at TREE_CONNECT with STATUS_ACCESS_DENIED.
func RequireEncryption() ShareOption { return func(s *share) { s.encrypt = true } }

// WithCapacity sets the total and available byte counts this share reports
// as its size and free space (FileFsSizeInformation and
// FileFsFullSizeInformation: what Explorer, Finder and `df` show).
//
// A share given neither this nor [WithCapacityFunc] reports a placeholder
// -- 4 GiB with 2 GiB free -- because the Filesystem contract has no statfs,
// and zero free would make a client refuse every write before trying. A
// caller that knows the size (it opened the image) or the free space (it
// serves a directory, a quota) says so here. A zero total means "unknown"
// and keeps the placeholder.
func WithCapacity(total, avail uint64) ShareOption {
	return WithCapacityFunc(func() (uint64, uint64) { return total, avail })
}

// WithCapacityFunc is [WithCapacity] asked at every query instead of once:
// for a share whose free space goes down with every write, or whose quota
// is resized while it is served.
//
// f runs on the connection's goroutine at every size query: it must be safe
// for concurrent use and must not block, because the client waits for it.
// A caller whose numbers are slow to obtain keeps the last ones it has and
// refreshes them elsewhere. Of the two options, the one given last wins; a
// nil f is the same as never giving either.
func WithCapacityFunc(f func() (total, avail uint64)) ShareOption {
	return func(s *share) { s.capacity = f }
}

// New returns a server with no shares and no users. A server with no users
// authenticates nobody: SMB has no anonymous mode worth offering, and a client
// asked to mount without credentials is told so rather than let in.
func New() *Server {
	s := &Server{
		shares:  map[string]*share{},
		users:   map[string]credential{},
		name:    "GOFS",
		conns:   map[*conn]struct{}{},
		closing: make(chan struct{}),
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
	s.users[user] = credential{password: password}
}

// AddUserHash adds a user whose password this server does not have, only its
// MD4 -- the "NT hash", which is what a directory keeps: Samba's
// sambaNTPassword attribute, or a column beside it in a database.
//
// It exists because NTLMv2 is a challenge-response. The client never sends the
// password, so the server must compute MD4(UTF16LE(password)) itself; a site
// whose people live in LDAP cannot answer that with a bind and cannot answer
// it with a bcrypt. The hash IS the credential here, which is worth being
// plain about: anybody holding it can authenticate as that person, exactly as
// if they held the password. It is not a password hash in the sense a login
// form means, and storing it does not make a leak less bad.
//
// The hash is 16 bytes. A shorter or longer one is refused rather than padded:
// a mangled hash would fail every login with "wrong password", which is the
// least useful thing a server could say.
func (s *Server) AddUserHash(user string, ntHash []byte) error {
	if len(ntHash) != 16 {
		return fmt.Errorf("smb: an NT hash is 16 bytes, not %d", len(ntHash))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user] = credential{ntHash: append([]byte(nil), ntHash...)}
	return nil
}

// RemoveUser forgets a user: their next authentication fails. A session
// already established is not cut, as removing an account from a directory
// does not unmount what somebody already has open.
func (s *Server) RemoveUser(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, user)
}

// A credential is what a server can prove somebody with: the password, or the
// MD4 of it. Both end in the same place -- NTOWFv2 is an HMAC keyed by that
// MD4 -- and the difference is only whether this server ever knew the
// password.
type credential struct {
	password string
	ntHash   []byte
}

// key is MD4(UTF16LE(password)), whichever way it arrived.
func (c credential) key() []byte {
	if len(c.ntHash) > 0 {
		return c.ntHash
	}
	return md4sum(utf16le(c.password))
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

func (s *Server) credentialFor(user string) (credential, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.users[user]
	return c, ok
}

func (s *Server) serverName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.name
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	if s.DisableNTLM && s.Kerberos == nil {
		return ErrNeedKerberos
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.lns = append(s.lns, ln)
	s.mu.Unlock()
	var backoff time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			// A failure to accept ONE connection is not the end of the listener:
			// EMFILE and ENFILE (out of descriptors, which a flood causes and the
			// end of the flood cures), ECONNABORTED (the peer left before it was
			// accepted) and the like are temporary. The loop waits, 5 ms doubling to
			// a second, as net/http's Server.Serve does, and tries again; only a
			// closed listener, or an error that is not temporary, ends it.
			if acceptRetryable(err) && !errors.Is(err, net.ErrClosed) {
				backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
				if backoff == 5*time.Millisecond { // once per streak of failures
					s.logAcceptError(err, backoff)
				}
				select {
				case <-time.After(backoff):
				case <-s.closing:
					return nil
				}
				continue
			}
			return err
		}
		backoff = 0
		c := newConn(s, nc)
		c.counted.Store(true)
		if !s.admit(c) {
			// Over a limit: closed here, before a goroutine or a buffer is spent.
			nc.Close()
			continue
		}
		go func() {
			defer s.release(c)
			c.serve()
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
	if s.closing != nil {
		close(s.closing) // wakes an accept loop that is waiting to try again
	}
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
	// clientDialects and clientGuid are what the client's NEGOTIATE said, kept for
	// FSCTL_VALIDATE_NEGOTIATE_INFO to compare against.
	connLimitState // see limits.go
	clientDialects []uint16
	clientGuid     [16]byte
	// seq is the command sequence window. It is nil until serve starts it, so a
	// test that drives dispatchChain by hand, with every request numbered 0, is not
	// refused for replaying itself; a window is tested on its own.
	seq *seqWindow
	// signingAlgorithm is the id negotiated by SMB2_SIGNING_CAPABILITIES
	// (AES-CMAC when none was); see sigAlgoFor.
	signingAlgorithm uint16
	// cipherID is the cipher negotiated by SMB2_ENCRYPTION_CAPABILITIES (3.1.1;
	// zero for none). See encCapable.
	cipherID uint16
	// preauth is the pre-authentication integrity hash after NEGOTIATE (3.1.1
	// only); each exchange continues it from there. See preauth.go.
	preauth []byte
	// exchanges are the authentications in progress, keyed by the session id the
	// server allocated to each, and exchangeOrder is the order they began in, for
	// dropping the oldest when there are too many. See session.go.
	exchanges     map[uint64]*exchange
	exchangeOrder []uint64
	nextID        uint64
	sessions      map[uint64]*session
	trees         map[uint32]*treeConn
	nextTree      uint32

	panicked any // what a connection died of, for a test to insist on
	files    map[[16]byte]*openFile
	nextFile uint64
	lastFile [16]byte // what an all-ones file id in a chained request means
	// searches remembers where a directory listing got to, keyed by the
	// handle it is being read through: SMB asks for a directory in pages and
	// expects the second page to continue the first.
	searches map[[16]byte]*search

	// A reply can now be written by a goroutine that is not the one reading
	// (see async.go), so writes are serialised and the state the two share is
	// locked. Before that the loop read one message, answered it and read the
	// next: everything was serial by construction, and none of this existed.
	wmu       sync.Mutex // one writer at a time
	mu        sync.Mutex // guards waiting and nextAsync
	waiting   map[uint64]*pendingOp
	nextAsync uint64
}

func newConn(s *Server, nc net.Conn) *conn {
	return &conn{
		srv: s, nc: nc,
		sessions: map[uint64]*session{},
		trees:    map[uint32]*treeConn{},
		files:    map[[16]byte]*openFile{},
		searches: map[[16]byte]*search{},
		waiting:  map[uint64]*pendingOp{},
	}
}

// A session is one authenticated user on one connection.
type session struct {
	user       string
	sessionKey []byte
	signingKey []byte
	// crypto is nil on a session that cannot encrypt; encryptData says every
	// message of it must be (Session.EncryptData, [MS-SMB2] 3.3.5.2.9).
	crypto      *sessionCrypto
	encryptData bool
	// signingRequired is Session.SigningRequired ([MS-SMB2] 3.3.5.5.3 step 5): the
	// client said, in its NEGOTIATE, that it requires signing. From then on a
	// request that arrives neither signed nor encrypted is refused.
	signingRequired bool
	// expires is Session.ExpirationTime ([MS-SMB2] 3.3.5.5.3 step 15): the end of
	// the Kerberos ticket the session was authenticated with. The zero time is
	// infinity, which is what NTLM gives.
	expires time.Time
}

func (c *conn) serve() {
	defer c.nc.Close()
	c.seq = newSeqWindow()
	c.startPreAuthClock()
	defer c.stopClocks() // a clock that outlived its connection would pin it
	// Registered first, so it runs last: nothing is in flight that could still
	// use the keys. (Sessions still open when the connection drops were never
	// logged off.)
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, s := range c.sessions {
			s.wipe()
		}
	}()
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
			// reserved for the life of the server, and an operation waiting
			// on a handle nobody has open will never complete on its own.
			of.share.locks.releaseAll(of.id)
			c.cancelForFile(of.id)
		}
	}()
	// The error is impossible: the writer is not nil, the order is one of the
	// two and the width is at least 1.
	cn, _ := c.srv.inflightPool().NewConn(frameSender{c}, inflight.AnyOrder, c.srv.maxInFlight())
	// Registered last so that it runs first: requests in flight are answered
	// (or fail on the closing stream) before the handles they use are closed.
	defer cn.Wait()
	pr := &prefixed{}
	for {
		if cn.Err() != nil {
			return
		}
		// Wait for the next frame to begin BEFORE taking a slot and a token: a
		// connection with nothing to say holds nothing of the server's budget.
		var first [1]byte
		if _, err := io.ReadFull(c.nc, first[:]); err != nil {
			return
		}
		sl, err := cn.Begin()
		if err != nil {
			return
		}
		// The slot and the token are held while the rest of the frame arrives,
		// so the time that takes is bounded: a client that sends half a frame
		// and stops must not hold the server's budget. The deadline is lifted
		// again afterwards, because waiting for the NEXT frame is not bounded.
		record := c.srv.recordTimeout()
		if record > 0 {
			_ = c.nc.SetReadDeadline(time.Now().Add(record))
		}
		pr.reset(c.nc, first[0])
		msg, err := readFrame(pr)
		if record > 0 {
			_ = c.nc.SetReadDeadline(time.Time{})
		}
		if err != nil {
			cn.Abandon(sl)
			return
		}
		c.touch() // the idle clock counts from the last request
		if span, ok := c.readSpan(msg); ok {
			cn.Go(sl, span, c.runner(msg))
		} else {
			cn.Barrier(sl, c.runner(msg))
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
//
// A frame that begins with a TRANSFORM_HEADER is decrypted first, and what the
// chain answers is encrypted again, as one unit, when the request was encrypted
// or when the session or the share it touched requires it ([MS-SMB2]
// 3.3.4.1.4).
func (c *conn) dispatchChain(msg []byte) ([]byte, error) {
	// The legacy greeting is not an SMB2 message and has no header to parse,
	// so it is answered before the loop that reads one. Putting this check
	// only inside dispatch is a mistake that costs a whole afternoon: the Go
	// client never sends the greeting, so the tests stay green while every
	// mount from macOS dies at the first frame, silently.
	if len(msg) >= 4 && [4]byte(msg[:4]) == smb1ProtocolID {
		// [MS-SMB2] 3.3.5.2.3: the server "MUST assume that MessageId is zero" for
		// the SMB1 negotiate, so it uses up id 0 like any other request.
		if c.seq != nil && !c.seq.take(0, 1) {
			return nil, errSequence
		}
		resp, err := c.legacyNegotiateResponse()
		c.noteReply(resp)
		return resp, err
	}
	encrypted, tsid := false, uint64(0)
	if len(msg) >= 4 && [4]byte(msg[:4]) == transformProtocolID {
		plain, sid, err := c.decryptFrame(msg)
		if err != nil {
			return nil, err
		}
		msg, encrypted, tsid = plain, true, sid
	}
	var seal sealing // who to encrypt the reply for; the zero value is "nobody"
	if encrypted {
		// decryptFrame found the session, which a LOGOFF in this very frame may
		// remove: the reply to it is still encrypted, so the keys are held here.
		seal = sealing{tsid, c.sessions[tsid].crypto}
	}
	out, err := c.chain(msg, encrypted, tsid, &seal)
	if err == nil {
		c.noteReply(out) // the credits it carries are ids the client may now use
	}
	if err != nil || out == nil || seal.crypto == nil {
		return out, err
	}
	return seal.crypto.seal(seal.sid, out), nil
}

// sealing names the session a reply is to be encrypted for, and its keys.
type sealing struct {
	sid    uint64
	crypto *sessionCrypto
}

// replyMustBeEncrypted is [MS-SMB2] 3.3.4.1.4 for a reply to an unencrypted
// request: everything but NEGOTIATE and SESSION_SETUP on a session that
// requires encryption, and everything but those and TREE_CONNECT on a share that
// does. (A reply to an encrypted request is always encrypted.)
func (c *conn) replyMustBeEncrypted(cmd command, sess *session, tree *treeConn) bool {
	if cmd == cmdNegotiate || cmd == cmdSessionSetup || sess == nil || sess.crypto == nil {
		return false
	}
	if sess.encryptData {
		return true
	}
	if cmd == cmdTreeConnect {
		return false
	}
	return tree != nil && tree.sh.encrypt
}

// chain is the loop of dispatchChain over plaintext requests. encrypted says the
// frame arrived encrypted for session tsid; *seal is set to the session to
// encrypt the reply for when a request of an unencrypted frame needs it.
func (c *conn) chain(msg []byte, encrypted bool, tsid uint64, seal *sealing) ([]byte, error) {
	var (
		out       []byte
		prevAt    = -1 // where the previous reply's header starts, inside out
		first     header
		haveFirst bool
		// prevStatus is what the previous request in this chain answered. A
		// RELATED request that follows a failure must not be carried out:
		// see below, and read the rename it cost.
		prevStatus = statusSuccess
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
		// [MS-SMB2] 3.3.5.2.1.1: inside an encrypted frame every operation that
		// is not related to the one before names the session the frame was
		// encrypted for, and the first one cannot be related to anything.
		if encrypted {
			if h.flags&flagRelatedOps == 0 {
				if binary.LittleEndian.Uint64(one[offSessionID:]) != tsid {
					return nil, errTransform
				}
			} else if !haveFirst {
				return nil, errTransform
			}
		}
		// [MS-SMB2] 3.3.5.2.3: the MessageId (and the CreditCharge ids after it) must
		// be in the window, and is used up. CANCEL skips this: it names the request
		// it cancels and consumes no id of its own (3.3.1.1). Each operation of a
		// compound has an id of its own and uses it up here, even one that is then
		// skipped for the failure before it.
		credited := uint16(0)
		if c.seq != nil && h.command != cmdCancel {
			if !c.seq.take(h.messageID, uint32(h.creditCharge)) {
				return nil, errSequence
			}
			// How many credits the reply grants is the server's to decide
			// ([MS-SMB2] 3.3.1.2): what the client asked for, but never so many
			// that it holds more than the connection is allowed (see creditCap).
			// Every reply built from this header, including a refusal, carries it.
			credited = c.seq.allow(creditsFor(h), c.creditCap())
			h.credits = credited
		}
		// The related-operations flag means this request speaks about what the
		// first one opened: it carries no session or tree of its own.
		if haveFirst && h.flags&flagRelatedOps != 0 {
			one = withInheritedIDs(one, first)
		}
		if !haveFirst {
			first, haveFirst = h, true
		}

		// A related request whose predecessor FAILED is not carried out. It
		// speaks about a file the previous operation did not open, and an
		// all-ones file id would then resolve to whatever this connection
		// opened last -- somebody else's live handle.
		//
		// This is what a rename from Windows costs. Windows checks the target
		// name with a compounded CREATE + CLOSE; the CREATE fails with
		// OBJECT_NAME_NOT_FOUND, as it should, and the CLOSE that follows it
		// closed the SOURCE file, which the client was still holding. Its next
		// SET_INFO came back FILE_CLOSED, and the rename failed with "The
		// handle is invalid" -- a message about a handle the server had shut
		// behind the client's back. macOS and Linux never send a chain whose
		// first operation fails, so nothing else here ever saw it.
		//
		// The status is the previous one, not an invented one: the client sees
		// the same reason twice and knows the chain did not happen.
		if h.flags&flagRelatedOps != 0 && prevStatus != statusSuccess {
			reply := compoundReply(errorResponse(h, prevStatus), h.nextCommand != 0)
			if h.flags&flagSigned != 0 {
				if sess := c.sessions[binary.LittleEndian.Uint64(one[offSessionID:])]; sess != nil {
					signMessage(c.signAlgo(), sess.signingKey, reply)
				}
			}
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
			if h.nextCommand == 0 {
				return out, nil
			}
			msg = msg[end:]
			continue
		}

		// A signed request is verified before it is read. A signature that
		// does not check out is not a request from the party that
		// authenticated, whatever it says in its header.
		//
		// A message that arrived encrypted was authenticated by its cipher, and
		// is not checked again ([MS-SMB2] 3.3.5.2.4: "and the message is not
		// encrypted").
		sess := c.sessions[binary.LittleEndian.Uint64(one[offSessionID:])]
		// [MS-SMB2] 3.3.5.2.9: every command but the ones that come before there is
		// a session names an authenticated session. Without this a request that
		// carries SessionId 0 and a tree id would reach the handlers with no
		// session to hold it to anything: not its signature, not its encryption.
		if sess == nil && commandNeedsSession(h.command) {
			return c.finish(out, prevAt, errorResponse(h, statusUserSessionDeleted), nil, h), nil
		}
		// [MS-SMB2] 3.3.5.2.9: a session whose Kerberos ticket has run out (its
		// ExpirationTime, 3.3.5.5.3 step 15) still processes LOGOFF, CLOSE and LOCK,
		// and fails the rest with STATUS_NETWORK_SESSION_EXPIRED, on which the client
		// authenticates again: the SESSION_SETUP that does it must get through.
		if sess != nil && !sess.expires.IsZero() && !time.Now().Before(sess.expires) {
			switch h.command {
			case cmdLogoff, cmdClose, cmdLock, cmdSessionSetup:
			default:
				c.logRefused(h, "the session's Kerberos ticket has expired")
				return c.finish(out, prevAt, errorResponse(h, statusSessionExpired), sess, h), nil
			}
		}
		signed := h.flags&flagSigned != 0 && !encrypted
		// [MS-SMB2] 3.3.5.2.4: "the server MUST determine if the client failed to
		// sign a packet that required it": an unsigned request on a session that
		// requires signing is refused. An encrypted one is authenticated by its
		// cipher, which is what an encrypting session uses instead of a
		// signature. CANCEL is verified only when it is signed (3.3.5.16).
		if !signed && !encrypted && sess != nil && sess.signingRequired && commandIsSigned(h.command) {
			c.logRefused(h, "not signed, and the session requires signing")
			return c.finish(out, prevAt, errorResponse(h, statusAccessDenied), sess, h), nil
		}
		if signed {
			if sess == nil || !verifyMessage(c.signAlgo(), sess.signingKey, one) {
				c.logRefused(h, "the signature does not verify")
				return c.finish(out, prevAt, errorResponse(h, statusAccessDenied), sess, h), nil
			}
		}

		// Encryption that a session or a share requires: a request that does not
		// come encrypted is refused, and the refusal is itself encrypted
		// ([MS-SMB2] 3.3.5.2.9, 3.3.5.2.11, 3.3.4.1.4).
		tree := c.treeOf(binary.LittleEndian.Uint64(one[offSessionID:]), binary.LittleEndian.Uint32(one[offTreeID:]))
		if !encrypted && c.encryptionRequired(h.command, sess, tree) {
			if c.replyMustBeEncrypted(h.command, sess, tree) && seal.crypto == nil {
				*seal = sealing{binary.LittleEndian.Uint64(one[offSessionID:]), sess.crypto}
			}
			return c.finish(out, prevAt, errorResponse(h, statusAccessDenied), sess, h), nil
		}
		if !encrypted && seal.crypto == nil && c.replyMustBeEncrypted(h.command, sess, tree) {
			*seal = sealing{binary.LittleEndian.Uint64(one[offSessionID:]), sess.crypto}
		}

		reply, err := c.dispatchEnc(one, encrypted, credited)
		if err != nil {
			return nil, err
		}
		if reply != nil {
			reply = compoundReply(reply, h.nextCommand != 0)
		}
		// Signed in kind: a client that signed its request checks the reply,
		// and one that did not would reject a signature it cannot verify.
		if reply != nil && signed && sess != nil {
			signMessage(c.signAlgo(), sess.signingKey, reply)
		}
		if h.command == cmdLogoff && sess != nil {
			sess.wipe() // the reply above was the last thing the keys were for
		}
		if reply != nil {
			if len(reply) >= headerLen {
				prevStatus = binary.LittleEndian.Uint32(reply[offStatus:])
			}
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

// compoundReply readies one reply of a chain for signing. When more requests
// follow in the chain, more replies will follow this one, so it is padded to an
// eight-byte boundary and its NextCommand says how far the next one is -- and this
// is done BEFORE it is signed, because the signature covers the whole header and
// "any padding at the end of the message MUST be used in the hash computation"
// ([MS-SMB2] 3.1.4.1). Signing first and padding after, which this server did,
// produced a signature no client that verifies compounded replies can accept:
// macOS, once the server required signing, dropped the mount after its first
// CREATE + QUERY_INFO + CLOSE.
func compoundReply(reply []byte, more bool) []byte {
	if !more || len(reply) < headerLen {
		return reply
	}
	for len(reply)%8 != 0 {
		reply = append(reply, 0)
	}
	binary.LittleEndian.PutUint32(reply[offNextCommand:], uint32(len(reply)))
	return reply
}

// commandNeedsSession is false for the commands that are legitimate with no
// session: NEGOTIATE and SESSION_SETUP come before one exists, ECHO is a
// keep-alive, and CANCEL only names an operation of this connection.
func commandNeedsSession(cmd command) bool {
	switch cmd {
	case cmdNegotiate, cmdSessionSetup, cmdEcho, cmdCancel:
		return false
	}
	return true
}

// commandIsSigned is true for the commands a session that requires signing must
// sign: all but the two that come before there is a session key, and CANCEL, which
// the specification verifies only if it is signed (3.3.5.16).
func commandIsSigned(cmd command) bool {
	switch cmd {
	case cmdNegotiate, cmdSessionSetup, cmdCancel:
		return false
	}
	return true
}

// finish appends one last reply to a chain and returns what to send. The
// refusal path uses it so a rejected signature still answers in the shape the
// client is reading.
func (c *conn) finish(out []byte, prevAt int, reply []byte, sess *session, h header) []byte {
	if sess != nil && h.flags&flagSigned != 0 {
		signMessage(c.signAlgo(), sess.signingKey, reply)
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

// encryptionRequired says a request must have arrived encrypted and did not:
// its session requires encryption, or the share its tree is connected to does
// ([MS-SMB2] 3.3.5.2.9 and 3.3.5.2.11). NEGOTIATE and SESSION_SETUP come before
// there is a session to ask, and TREE_CONNECT is how the share's own rule is
// announced, so only the session's rule applies to it.
//
// The tree is the one in the REQUEST'S OWN SESSION (see treeOf): a tree id that
// belongs to another session is no tree, not a way round the share's rule.
func (c *conn) encryptionRequired(cmd command, sess *session, tree *treeConn) bool {
	if cmd == cmdNegotiate || cmd == cmdSessionSetup || sess == nil {
		return false
	}
	if sess.encryptData {
		return true
	}
	if cmd == cmdTreeConnect {
		return false
	}
	return tree != nil && tree.sh.encrypt
}

// dispatch answers one message. An error stops the connection; a nil response
// means there is nothing to send back.
func (c *conn) dispatch(msg []byte) ([]byte, error) {
	return c.dispatchEnc(msg, false, 0)
}

// dispatchEnc is dispatch for a message that did, or did not, arrive encrypted:
// an operation that answers later must answer encrypted too.
//
// credits, when not zero, is how many credits the reply grants: it is set on the
// parsed header and not written into the message, because the message is what a
// signature and the pre-authentication hash were computed over.
func (c *conn) dispatchEnc(msg []byte, encrypted bool, credits uint16) ([]byte, error) {
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
	h.encrypted = encrypted
	if credits != 0 {
		h.credits = credits
	}
	body := msg[headerLen:]
	if c.dialect != 0 && h.command != cmdNegotiate && creditChargeTooLow(h, body) {
		return errorResponse(h, statusInvalidParameter), nil
	}
	switch h.command {
	case cmdNegotiate:
		return c.negotiate(h, body, msg)
	case cmdSessionSetup:
		return c.sessionSetup(h, body, msg)
	case cmdLogoff:
		return c.logoff(h), nil
	case cmdTreeConnect:
		return c.treeConnect(h, body, msg)
	case cmdTreeDisconnect:
		// Only the session's own tree: another session's id is not ours to drop.
		if c.tree(h) != nil {
			delete(c.trees, h.treeID)
		}
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
	case cmdCancel:
		return c.cancel(h)
	case cmdChangeNotify:
		return c.changeNotify(h, body)
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
