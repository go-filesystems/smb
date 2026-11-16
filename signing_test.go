package smb

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Session.SigningRequired, [MS-SMB2] 3.3.5.5.3 step 5 and 3.3.5.2.4.

func requiringConn(t *testing.T) (*conn, []byte) {
	t.Helper()
	c := newConn(New(), nil)
	c.dialect = dialect302
	key := bytes.Repeat([]byte{3}, 16)
	c.sessions[1] = &session{user: "alice", sessionKey: key, signingKey: key, signingRequired: true}
	c.trees[5] = &treeConn{sh: &share{name: "disk", fsys: nothingFS{}}, session: 1}
	return c, key
}

func signedRequest(c *conn, key []byte, cmd command, body []byte) []byte {
	m := requestIn(cmd, 1, 5, body)
	signMessage(c.signAlgo(), key, m)
	return m
}

// An unsigned request on a session that requires signing is refused, whatever it
// asks for: stripping the signature is the one thing signing exists to stop.
func TestAnUnsignedRequestOnASessionThatRequiresSigning(t *testing.T) {
	c, key := requiringConn(t)
	for _, cmd := range []command{cmdEcho, cmdLogoff, cmdTreeConnect, cmdTreeDisconnect, cmdCreate, cmdClose,
		cmdFlush, cmdRead, cmdWrite, cmdLock, cmdIoctl, cmdQueryDirectory, cmdChangeNotify, cmdQueryInfo, cmdSetInfo} {
		out, err := c.dispatchChain(requestIn(cmd, 1, 5, make([]byte, 64)))
		if err != nil {
			t.Fatalf("%v: %v", cmd, err)
		}
		if st := statusOf(t, out); st != statusAccessDenied {
			t.Errorf("an unsigned %v answered %#x, want ACCESS_DENIED", cmd, st)
		}
	}
	if c.sessions[1] == nil || c.trees[5] == nil {
		t.Error("a refused request took the session or its tree with it")
	}
	// The same request, signed, is carried out.
	out, err := c.dispatchChain(signedRequest(c, key, cmdClose, make([]byte, 24)))
	if err != nil || statusOf(t, out) != statusFileClosed {
		t.Errorf("a signed CLOSE: %v %#x (the handle is not there, the request was not refused)", err, statusOf(t, out))
	}
	// A signature that does not verify is refused too (the existing rule).
	bad := signedRequest(c, key, cmdClose, make([]byte, 24))
	bad[offSignature] ^= 1
	if out, _ := c.dispatchChain(bad); statusOf(t, out) != statusAccessDenied {
		t.Error("a bad signature was accepted")
	}
	// CANCEL is verified only when it is signed (3.3.5.16); NEGOTIATE and
	// SESSION_SETUP come before there is a key.
	if _, err := c.dispatchChain(requestIn(cmdCancel, 1, 5, []byte{4, 0, 0, 0})); err != nil {
		t.Errorf("an unsigned CANCEL: %v", err)
	}
}

// A session that did not ask for signing is not held to it, and an encrypted
// request is authenticated by its cipher.
func TestOnlyASessionThatRequiresSigningIsHeldToIt(t *testing.T) {
	c, _ := requiringConn(t)
	c.sessions[1].signingRequired = false
	out, err := c.dispatchChain(requestIn(cmdClose, 1, 5, make([]byte, 24)))
	if err != nil || statusOf(t, out) != statusFileClosed {
		t.Errorf("an unsigned request on a session that does not require signing: %v %#x", err, statusOf(t, out))
	}

	p := newEncPair(t, dialect311, cipherAES128GCM)
	p.sess.signingRequired = true
	p.sess.signingKey = bytes.Repeat([]byte{4}, 16)
	out, err = p.c.dispatchChain(echoFrame(p, p.sid))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := p.client.open(out)
	if err != nil || statusOf(t, plain) != statusSuccess {
		t.Errorf("an encrypted request on a session that requires signing: %v", err)
	}
}

// [MS-SMB2] 3.3.5.7: on 3.1.1 a TREE_CONNECT that is neither signed nor encrypted
// ends the connection.
func TestAnUnprotectedTreeConnectOn311(t *testing.T) {
	path := utf16le(`\\host\disk`)
	mk := func(flags uint32) []byte {
		body := make([]byte, 8)
		putU16(body[0:], 9)
		putU16(body[4:], headerLen+8)
		putU16(body[6:], uint16(len(path)))
		m := append(requestOf(cmdTreeConnect, body), path...)
		binary.LittleEndian.PutUint64(m[offSessionID:], 1)
		putU32(m[offFlags:], flags)
		return m
	}
	build := func(dialect uint16) *conn {
		c := newConn(New(), nil)
		c.dialect = dialect
		c.sessions[1] = &session{user: "alice"}
		c.srv.Share("disk", nothingFS{})
		return c
	}
	if _, err := build(dialect311).dispatchEnc(mk(0), false); err == nil {
		t.Error("an unprotected TREE_CONNECT was answered on 3.1.1")
	}
	if out, err := build(dialect311).dispatchEnc(mk(flagSigned), false); err != nil || statusOf(t, out) != statusSuccess {
		t.Errorf("a signed TREE_CONNECT on 3.1.1: %v", err)
	}
	if out, err := build(dialect311).dispatchEnc(mk(0), true); err != nil || statusOf(t, out) != statusSuccess {
		t.Errorf("an encrypted TREE_CONNECT on 3.1.1: %v", err)
	}
	// Before 3.1.1 the rule does not exist.
	if out, err := build(dialect302).dispatchEnc(mk(0), false); err != nil || statusOf(t, out) != statusSuccess {
		t.Errorf("an unsigned TREE_CONNECT on 3.0.2: %v", err)
	}
}
