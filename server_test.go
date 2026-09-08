package smb

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

type nothingFS struct{}

func (nothingFS) ReadFile(string) ([]byte, error)               { return nil, os.ErrNotExist }
func (nothingFS) WriteFile(string, []byte, os.FileMode) error   { return os.ErrPermission }
func (nothingFS) ListDir(string) ([]filesystem.DirEntry, error) { return nil, nil }
func (nothingFS) MkDir(string, os.FileMode) error               { return os.ErrPermission }
func (nothingFS) Stat(string) (filesystem.Stat, error)          { return nil, os.ErrNotExist }
func (nothingFS) DeleteFile(string) error                       { return os.ErrPermission }
func (nothingFS) DeleteDir(string) error                        { return os.ErrPermission }
func (nothingFS) Rename(string, string) error                   { return os.ErrPermission }
func (nothingFS) Truncate(string, int64) error                  { return os.ErrPermission }
func (nothingFS) Symlink(string, string) error                  { return os.ErrPermission }
func (nothingFS) ReadLink(string) (string, error)               { return "", os.ErrNotExist }
func (nothingFS) Label() string                                 { return "NOTHING" }
func (nothingFS) Close() error                                  { return nil }

// A share name is a name, not a path, and two shares cannot answer to one.
func TestShareRefusals(t *testing.T) {
	s := New()
	for _, tc := range []struct {
		name string
		give string
		fsys filesystem.Filesystem
		want string
	}{
		{"no name", "", nothingFS{}, "needs a name"},
		{"a path instead of a name", `sub\dir`, nothingFS{}, "path separator"},
		{"a forward slash too", "sub/dir", nothingFS{}, "path separator"},
		{"no filesystem", "disk", nil, "needs a filesystem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Share(tc.give, tc.fsys)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
	if err := s.Share("disk", nothingFS{}); err != nil {
		t.Fatal(err)
	}
	// The name is compared without case, so the second one is the same share.
	if err := s.Share("DISK", nothingFS{}); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("a second share under the same name: %v", err)
	}
	if s.shareByName("dIsK") == nil {
		t.Error("the share cannot be found under another case")
	}
	if s.shareByName("other") != nil {
		t.Error("a share that was never added was found")
	}
}

// A read-only share is refused the write bits in the access mask the client is
// handed, so a file manager greys the actions out instead of offering them.
func TestReadOnlyIsSaidInTheAccessMask(t *testing.T) {
	s := New()
	if err := s.Share("ro", nothingFS{}, ReadOnly()); err != nil {
		t.Fatal(err)
	}
	if !s.shareByName("ro").ro {
		t.Error("ReadOnly did not take")
	}
	// READ_CONTROL and SYNCHRONIZE are in both masks, and belong in both. What
	// a read-only share must not carry is the bits that write: data, append,
	// extended attributes, attributes.
	const writesData = 0x0002 | 0x0004 | 0x0010 | 0x0100
	if accessRead&writesData != 0 {
		t.Errorf("the read mask carries write bits: %#x", accessRead&writesData)
	}
	if accessWrite&writesData == 0 {
		t.Error("the write mask carries none of the bits that write")
	}
}

func TestNameAndUsers(t *testing.T) {
	s := New()
	if s.serverName() == "" {
		t.Error("a server with no name set has none at all")
	}
	s.SetName("TESTBOX")
	if s.serverName() != "TESTBOX" {
		t.Errorf("name = %q", s.serverName())
	}
	if _, ok := s.password("nobody"); ok {
		t.Error("a user nobody added has a password")
	}
	s.AddUser("alice", "hunter2")
	if p, ok := s.password("alice"); !ok || p != "hunter2" {
		t.Errorf("password = %q, %v", p, ok)
	}
}

// Close stops the listeners, and a second Close is not an error: a server is
// often closed by a defer and by the thing that noticed the failure.
func TestListenAndClose(t *testing.T) {
	s := New()
	errc := make(chan error, 1)
	go func() { errc <- s.ListenAndServe("127.0.0.1:0") }()
	// Give Serve a moment to register the listener, then close.
	for i := 0; i < 100; i++ {
		s.mu.Lock()
		n := len(s.lns)
		s.mu.Unlock()
		if n > 0 {
			break
		}
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("a second Close: %v", err)
	}
	// Either outcome is right, and which one happens is a race with the
	// goroutine starting: Serve returns nil when it was accepting and the
	// listener closed under it, and net.ErrClosed when Close won and it never
	// started. What must not happen is some other error.
	if err := <-errc; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("ListenAndServe returned %v after Close", err)
	}
	if err := s.ListenAndServe("127.0.0.1:0"); err == nil {
		t.Error("a closed server started listening again")
	}
	if err := s.Serve(nil); err == nil {
		t.Error("a closed server accepted a listener")
	}
	if err := s.ListenAndServe("nonsense:address:1"); err == nil {
		t.Error("an address that is not one was accepted")
	}
}

// The legacy greeting is answered without being read: whatever an SMB1 client
// says, the reply is "let us speak SMB2".
func TestTheLegacyGreetingIsAnswered(t *testing.T) {
	c := &conn{srv: New()}
	out, err := c.dispatch(append(smb1ProtocolID[:], 0x72, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseHeader(out)
	if err != nil {
		t.Fatal(err)
	}
	if h.command != cmdNegotiate {
		t.Errorf("the answer is a %v", h.command)
	}
	if got := dialectOf(out); got != dialectWildcard {
		t.Errorf("dialect = %#04x, want the wildcard %#04x", got, dialectWildcard)
	}
}

// A dialect nobody offered is not chosen: the client would have no way to read
// what came after.
func TestADialectWeDoNotSpeak(t *testing.T) {
	c := &conn{srv: New()}
	out, err := c.dispatch(negotiateRequest(dialect202, dialect300))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := parseHeader(out)
	if h.status != statusNotSupported {
		t.Errorf("status = %#x, want NOT_SUPPORTED", h.status)
	}
	// …and one we do speak is.
	out, err = c.dispatch(negotiateRequest(dialect202, dialect210, dialect311))
	if err != nil {
		t.Fatal(err)
	}
	if got := dialectOf(out); got != dialect210 {
		t.Errorf("dialect = %#04x, want %#04x", got, dialect210)
	}
	if c.dialect != dialect210 {
		t.Errorf("the connection remembers %#04x", c.dialect)
	}
	if _, err := c.dispatch(shortMessage(cmdNegotiate)); err == nil {
		t.Error("a NEGOTIATE too short to read was accepted")
	}
}

// Everything not implemented yet answers by name, so a client reports or falls
// back instead of waiting for a reply that never comes.
func TestWhatIsNotImplementedSaysSo(t *testing.T) {
	c := &conn{srv: New(), sessions: map[uint64]*session{}, trees: map[uint32]*share{}}
	for _, cmd := range []command{cmdCreate, cmdRead, cmdWrite, cmdQueryDirectory, cmdQueryInfo} {
		out, err := c.dispatch(requestOf(cmd, nil))
		if err != nil {
			t.Fatalf("%v: %v", cmd, err)
		}
		h, _ := parseHeader(out)
		if h.status != statusNotImplemented {
			t.Errorf("%v answered %#x, want NOT_IMPLEMENTED", cmd, h.status)
		}
	}
	// Echo, logoff and tree disconnect are answered, not refused.
	for _, cmd := range []command{cmdEcho, cmdLogoff, cmdTreeDisconnect} {
		out, err := c.dispatch(requestOf(cmd, nil))
		if err != nil {
			t.Fatalf("%v: %v", cmd, err)
		}
		if h, _ := parseHeader(out); h.status != statusSuccess {
			t.Errorf("%v answered %#x", cmd, h.status)
		}
	}
	// A tree connect from a connection with no session is refused.
	out, err := c.dispatch(requestOf(cmdTreeConnect, make([]byte, 8)))
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := parseHeader(out); h.status != statusUserSessionDeleted {
		t.Errorf("an unauthenticated TREE_CONNECT answered %#x", h.status)
	}
	if _, err := c.dispatch([]byte{1, 2, 3}); err == nil {
		t.Error("a message that is not a message was accepted")
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func dialectOf(response []byte) uint16 {
	return leU16(response[headerLen+4:])
}

func negotiateRequest(dialects ...uint16) []byte {
	body := make([]byte, 36+2*len(dialects))
	putU16(body[0:], 36)
	putU16(body[2:], uint16(len(dialects)))
	for i, d := range dialects {
		putU16(body[36+2*i:], d)
	}
	return requestOf(cmdNegotiate, body)
}

func shortMessage(cmd command) []byte { return requestOf(cmd, []byte{1, 2}) }

func requestOf(cmd command, body []byte) []byte {
	h := responseTo(header{command: cmd}, statusSuccess)
	putU32(h[offFlags:], 0) // a request, not a response
	return append(h, body...)
}

func putU16(b []byte, v uint16) { binary.LittleEndian.PutUint16(b, v) }
func putU32(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }
func leU16(b []byte) uint16     { return binary.LittleEndian.Uint16(b) }
