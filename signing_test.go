package smb

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Session.SigningRequired, [MS-SMB2] 3.3.5.5.3 step 5 and 3.3.5.2.4.
//
// These run the way serve() runs: with the command sequence window on, so every
// request carries an id the window holds, and the signature is checked by the
// real verification and not assumed from a flag.

// A requester numbers the requests it makes of one connection.
type requester struct {
	c    *conn
	key  []byte
	next uint64
}

func requiringConn(t *testing.T, dialect uint16) *requester {
	t.Helper()
	c := newConn(New(), nil)
	c.dialect = dialect
	c.seq = newSeqWindow()
	c.seq.limit = 1 << 20 // every id the test uses has been granted
	key := bytes.Repeat([]byte{3}, 16)
	c.sessions[1] = &session{user: "alice", sessionKey: key, signingKey: key, signingRequired: true}
	c.trees[5] = &treeConn{sh: &share{name: "disk", fsys: nothingFS{}}, session: 1}
	return &requester{c: c, key: key}
}

// unsigned is a request as an attacker who stripped the signature would send it
// (with its own, valid, id).
func (r *requester) unsigned(cmd command, body []byte) []byte {
	m := requestIn(cmd, 1, 5, body)
	binary.LittleEndian.PutUint64(m[offMessageID:], r.next)
	r.next++
	return m
}

func (r *requester) signed(cmd command, body []byte) []byte {
	m := r.unsigned(cmd, body)
	signMessage(r.c.signAlgo(), r.key, m)
	return m
}

// An unsigned request on a session that requires signing is refused, whatever it
// asks for: stripping the signature is the one thing signing exists to stop.
func TestAnUnsignedRequestOnASessionThatRequiresSigning(t *testing.T) {
	r := requiringConn(t, dialect302)
	c := r.c
	for _, cmd := range []command{cmdEcho, cmdLogoff, cmdTreeConnect, cmdTreeDisconnect, cmdCreate, cmdClose,
		cmdFlush, cmdRead, cmdWrite, cmdLock, cmdIoctl, cmdQueryDirectory, cmdChangeNotify, cmdQueryInfo, cmdSetInfo} {
		out, err := c.dispatchChain(r.unsigned(cmd, make([]byte, 64)))
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
	out, err := c.dispatchChain(r.signed(cmdClose, make([]byte, 24)))
	if err != nil || statusOf(t, out) != statusFileClosed {
		t.Errorf("a signed CLOSE: %v %#x (the handle is not there, the request was not refused)", err, statusOf(t, out))
	}
	// The signed flag is not a signature: a request that SAYS it is signed and
	// carries a wrong one, or none, goes through the real verification and fails.
	forged := r.unsigned(cmdClose, make([]byte, 24))
	binary.LittleEndian.PutUint32(forged[offFlags:], flagSigned)
	if out, _ := c.dispatchChain(forged); statusOf(t, out) != statusAccessDenied {
		t.Errorf("a request with the signed flag and no signature answered %#x", statusOf(t, out))
	}
	bad := r.signed(cmdClose, make([]byte, 24))
	bad[offSignature] ^= 1
	if out, _ := c.dispatchChain(bad); statusOf(t, out) != statusAccessDenied {
		t.Error("a bad signature was accepted")
	}
	// CANCEL is verified only when it is signed (3.3.5.16): an unsigned one is not
	// refused for that. NEGOTIATE and SESSION_SETUP come before there is a key.
	if _, err := c.dispatchChain(requestIn(cmdCancel, 1, 5, []byte{4, 0, 0, 0})); err != nil {
		t.Errorf("an unsigned CANCEL: %v", err)
	}
}

// A session that did not ask for signing is not held to it, and an encrypted
// request is authenticated by its cipher.
func TestOnlyASessionThatRequiresSigningIsHeldToIt(t *testing.T) {
	r := requiringConn(t, dialect302)
	r.c.sessions[1].signingRequired = false
	out, err := r.c.dispatchChain(r.unsigned(cmdClose, make([]byte, 24)))
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
// ends the connection. "Signed" means signed: the flag alone, with no signature
// or a wrong one, is refused by the verification and not accepted on its word.
func TestAnUnprotectedTreeConnectOn311(t *testing.T) {
	path := utf16le(`\\host\disk`)
	mk := func(r *requester, flags uint32, sign bool) []byte {
		body := make([]byte, 8)
		putU16(body[0:], 9)
		putU16(body[4:], headerLen+8)
		putU16(body[6:], uint16(len(path)))
		m := append(requestOf(cmdTreeConnect, body), path...)
		binary.LittleEndian.PutUint64(m[offSessionID:], 1)
		binary.LittleEndian.PutUint64(m[offMessageID:], r.next)
		r.next++
		putU32(m[offFlags:], flags)
		if sign {
			signMessage(r.c.signAlgo(), r.key, m)
		}
		return m
	}
	build := func(dialect uint16) *requester {
		r := requiringConn(t, dialect)
		r.c.sessions[1].signingRequired = false // the rule is about the dialect, not the flag
		r.c.srv.Share("disk", nothingFS{})
		return r
	}

	r := build(dialect311)
	if out, err := r.c.dispatchChain(mk(r, 0, false)); err == nil {
		t.Errorf("an unprotected TREE_CONNECT was answered on 3.1.1 (%#x)", statusOf(t, out))
	}
	r = build(dialect311)
	if out, err := r.c.dispatchChain(mk(r, flagSigned, false)); err != nil || statusOf(t, out) != statusAccessDenied {
		t.Errorf("a TREE_CONNECT that says it is signed and is not: %v %#x, want ACCESS_DENIED from the verification", err, statusOf(t, out))
	}
	r = build(dialect311)
	if out, err := r.c.dispatchChain(mk(r, 0, true)); err != nil || statusOf(t, out) != statusSuccess {
		t.Errorf("a signed TREE_CONNECT on 3.1.1: %v %#x", err, statusOf(t, out))
	}
	// Encrypted: through an encrypting pair, the real decryption.
	p := newEncPair(t, dialect311, cipherAES128GCM)
	p.c.seq = newSeqWindow()
	p.c.seq.limit = 1 << 20
	p.c.srv.Share("disk", nothingFS{})
	tc := mk(&requester{c: p.c, key: nil}, 0, false)
	binary.LittleEndian.PutUint64(tc[offSessionID:], p.sid)
	out, err := p.c.dispatchChain(p.client.seal(p.sid, tc))
	if err != nil {
		t.Fatalf("an encrypted TREE_CONNECT on 3.1.1: %v", err)
	}
	if plain, err := p.client.open(out); err != nil || statusOf(t, plain) != statusSuccess {
		t.Errorf("an encrypted TREE_CONNECT on 3.1.1: %v", err)
	}
	// Before 3.1.1 the rule does not exist.
	r = build(dialect302)
	if out, err := r.c.dispatchChain(mk(r, 0, false)); err != nil || statusOf(t, out) != statusSuccess {
		t.Errorf("an unsigned TREE_CONNECT on 3.0.2: %v", err)
	}
}
