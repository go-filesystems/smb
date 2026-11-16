package smb

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// Sessions own their trees, their handles and their pending operations, and
// nothing is reachable without one ([MS-SMB2] 3.3.5.2.9, 3.3.5.2.11).

// sessionConn is a connection with two authenticated sessions, 1 and 2, and a
// tree connected in session 1.
func sessionConn(t *testing.T) *conn {
	t.Helper()
	c := newConn(New(), nil)
	c.dialect = dialect302
	c.sessions[1] = &session{user: "alice", sessionKey: bytes.Repeat([]byte{1}, 16), signingKey: bytes.Repeat([]byte{1}, 16)}
	c.sessions[2] = &session{user: "bob", sessionKey: bytes.Repeat([]byte{2}, 16), signingKey: bytes.Repeat([]byte{2}, 16)}
	c.trees[5] = &treeConn{sh: &share{name: "disk", fsys: nothingFS{}}, session: 1}
	return c
}

func requestIn(cmd command, session uint64, tree uint32, body []byte) []byte {
	m := requestOf(cmd, body)
	binary.LittleEndian.PutUint64(m[offSessionID:], session)
	binary.LittleEndian.PutUint32(m[offTreeID:], tree)
	return m
}

// A request that names no session, or one that does not exist, is not carried
// out. Before this check a plaintext FLUSH with SessionId 0 and the TreeId of an
// encrypting share was executed and answered in the clear.
func TestARequestWithoutASessionIsRefused(t *testing.T) {
	for _, cmd := range []command{cmdLogoff, cmdTreeConnect, cmdTreeDisconnect, cmdCreate, cmdClose,
		cmdFlush, cmdRead, cmdWrite, cmdLock, cmdIoctl, cmdQueryDirectory, cmdChangeNotify, cmdQueryInfo, cmdSetInfo} {
		for _, sid := range []uint64{0, 99} {
			c := sessionConn(t)
			out, err := c.dispatchChain(requestIn(cmd, sid, 5, make([]byte, 64)))
			if err != nil {
				t.Fatalf("%v: %v", cmd, err)
			}
			if st := statusOf(t, out); st != statusUserSessionDeleted {
				t.Errorf("%v with session %d answered %#x, want USER_SESSION_DELETED", cmd, sid, st)
			}
		}
	}
	// The commands that come before there is a session, and the keep-alive, are
	// not refused for lacking one.
	c := sessionConn(t)
	if out, _ := c.dispatchChain(requestIn(cmdEcho, 0, 0, []byte{4, 0, 0, 0})); statusOf(t, out) != statusSuccess {
		t.Error("ECHO refused")
	}
	// (These two fail for reasons of their own, as bodies of zeros do; what matters
	// is that the reason is not the missing session.)
	for _, cmd := range []command{cmdNegotiate, cmdSessionSetup} {
		out, err := c.dispatchChain(requestIn(cmd, 0, 0, make([]byte, 36)))
		if err == nil && statusOf(t, out) == statusUserSessionDeleted {
			t.Errorf("%v refused for lacking a session", cmd)
		}
	}
}

// A tree id is looked up in the session that sent it: another session naming it
// finds nothing, and cannot disconnect it either.
func TestATreeBelongsToItsSession(t *testing.T) {
	c := sessionConn(t)
	out, _ := c.dispatchChain(requestIn(cmdCreate, 2, 5, make([]byte, 56)))
	if st := statusOf(t, out); st != statusNetworkNameDeleted {
		t.Errorf("session 2 using session 1's tree: %#x, want NETWORK_NAME_DELETED", st)
	}
	c.dispatchChain(requestIn(cmdTreeDisconnect, 2, 5, []byte{4, 0, 0, 0}))
	if c.trees[5] == nil {
		t.Error("session 2 disconnected session 1's tree")
	}
	// The owner's own request reaches the handler (which fails for its own reason:
	// the handle is not there).
	out, _ = c.dispatchChain(requestIn(cmdClose, 1, 5, make([]byte, 24)))
	if st := statusOf(t, out); st != statusFileClosed {
		t.Errorf("session 1 using its tree: %#x, want FILE_CLOSED", st)
	}
}

// LOGOFF takes the session's trees, handles and pending operations with it, and
// wipes its keys once the reply that needed them is signed.
func TestLogoffTakesEverythingTheSessionOwned(t *testing.T) {
	c := sessionConn(t)
	own := &openFile{path: "/a", share: c.trees[5].sh, session: 1}
	own.id[0] = 1
	other := &openFile{path: "/b", share: c.trees[5].sh, session: 2}
	other.id[0] = 2
	c.files[own.id], c.files[other.id] = own, other
	opn := &pendingOp{session: 1, asyncID: 7, cancel: make(chan struct{})}
	oth := &pendingOp{session: 2, asyncID: 8, cancel: make(chan struct{})}
	c.waiting[7], c.waiting[8] = opn, oth
	key := bytes.Repeat([]byte{1}, 16)
	sess := c.sessions[1]

	req := requestIn(cmdLogoff, 1, 0, []byte{4, 0, 0, 0})
	signMessage(c.signAlgo(), key, req)
	out, err := c.dispatchChain(req)
	if err != nil {
		t.Fatal(err)
	}
	if st := statusOf(t, out); st != statusSuccess {
		t.Fatalf("LOGOFF answered %#x", st)
	}
	// The reply was signed while the key was still there.
	if !verifyMessage(c.signAlgo(), key, out) {
		t.Error("the LOGOFF reply is not signed with the session's key")
	}
	if c.sessions[1] != nil || c.sessions[2] == nil {
		t.Error("LOGOFF removed the wrong sessions")
	}
	if c.trees[5] != nil {
		t.Error("the session's tree survived its LOGOFF")
	}
	if c.files[own.id] != nil || c.files[other.id] == nil {
		t.Error("LOGOFF closed the wrong handles")
	}
	if _, live := c.waiting[7]; live {
		t.Error("the session's pending operation survived")
	}
	if _, live := c.waiting[8]; !live {
		t.Error("another session's pending operation was ended")
	}
	select {
	case <-opn.cancel:
	default:
		t.Error("the session's pending operation was not woken")
	}
	if !bytes.Equal(sess.sessionKey, make([]byte, 16)) || !bytes.Equal(sess.signingKey, make([]byte, 16)) {
		t.Errorf("the keys were not wiped: %x %x", sess.sessionKey, sess.signingKey)
	}
	if !bytes.Equal(c.sessions[2].signingKey, bytes.Repeat([]byte{2}, 16)) {
		t.Error("another session's key was wiped")
	}
}

// An answer sent later is signed with the key of the session that asked, and is
// dropped, never sent as it is, when that session is gone.
func TestAnAnswerSentLaterBelongsToItsSession(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	c := sessionConn(t)
	c.nc = srv
	keyA, keyB := c.sessions[1].signingKey, c.sessions[2].signingKey

	read := func() ([]byte, bool) {
		cli.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		b, err := readFrame(cli)
		return b, err == nil
	}
	reply := func(op *pendingOp) []byte {
		return asyncResponse(header{command: op.command, messageID: op.messageID}, statusSuccess, op.asyncID, 9)
	}

	// Session 1's operation, while session 2 is the one that asked last: it must
	// be signed with session 1's key.
	op := &pendingOp{session: 1, asyncID: 3, cancel: make(chan struct{})}
	c.waiting[3] = op
	go c.finishAsync(op, reply(op))
	got, ok := read()
	if !ok {
		t.Fatal("no answer")
	}
	if !verifyMessage(c.signAlgo(), keyA, got) {
		t.Error("the answer is not signed with the key of the session that asked")
	}
	if verifyMessage(c.signAlgo(), keyB, got) {
		t.Error("the answer is signed with another session's key")
	}

	// The session is gone: nothing is sent at all.
	gone := &pendingOp{session: 77, asyncID: 4, cancel: make(chan struct{})}
	c.waiting[4] = gone
	go c.finishAsync(gone, reply(gone))
	if b, ok := read(); ok {
		t.Errorf("an answer for a session that is gone was sent: %x", b[:min(len(b), 16)])
	}
}
