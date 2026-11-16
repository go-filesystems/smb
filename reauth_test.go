package smb

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"testing"
	"time"
)

// Authenticating again as an existing session, and choosing a session id
// ([MS-SMB2] 3.3.5.5, 3.3.5.5.2). The first test is the independent review's
// repro, ported: an UNSIGNED SESSION_SETUP naming another user's live session id
// and carrying valid credentials of its own replaced that session's user while
// its trees and handles stayed bound to the id.

func (r *requester) setup(sid uint64, token []byte, sign bool) []byte {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:], 25)
	binary.LittleEndian.PutUint16(body[12:], uint16(headerLen+24))
	binary.LittleEndian.PutUint16(body[14:], uint16(len(token)))
	m := requestIn(cmdSessionSetup, sid, 0, append(body, token...))
	binary.LittleEndian.PutUint64(m[offMessageID:], r.next)
	r.next++
	if sign {
		signMessage(r.c.signAlgo(), r.key, m)
	}
	return m
}

func ntlmType1() []byte {
	neg := make([]byte, 32)
	copy(neg, ntlmSignature[:])
	binary.LittleEndian.PutUint32(neg[8:], ntlmNegotiate)
	return neg
}

func ntlmType3(ch *challenge, user, password string) []byte {
	blob := []byte{0x01, 0x01, 0, 0, 0, 0, 0, 0}
	blob = append(blob, filetimeBytes(time.Now())...)
	blob = append(blob, 1, 2, 3, 4, 5, 6, 7, 8)
	blob = append(blob, 0, 0, 0, 0)
	blob = append(blob, ch.targetInfo...)
	blob = append(blob, 0, 0, 0, 0)
	mac := hmac.New(md5.New, ntowfv2(user, "WORKGROUP", credential{password: password}))
	mac.Write(ch.nonce[:])
	mac.Write(blob)
	nt := append(mac.Sum(nil), blob...)
	msg := make([]byte, 64)
	copy(msg, ntlmSignature[:])
	binary.LittleEndian.PutUint32(msg[8:], ntlmAuth)
	u, d := utf16le(user), utf16le("WORKGROUP")
	off := uint32(64)
	putField(msg[20:], len(nt), off)
	off += uint32(len(nt))
	putField(msg[28:], len(d), off)
	off += uint32(len(d))
	putField(msg[36:], len(u), off)
	msg = append(msg, nt...)
	msg = append(msg, d...)
	return append(msg, u...)
}

// reauthConn is a connection where alice holds session 1 (signing required, a
// tree, a handle) and mallory has a valid account.
func reauthConn(t *testing.T) (*requester, *session, *openFile) {
	t.Helper()
	r := requiringConn(t, dialect302)
	r.c.srv.AddUser("mallory", "pw")
	r.c.srv.AddUser("alice", "hunter2")
	of := &openFile{path: "/a", share: r.c.trees[5].sh, session: 1}
	of.id[0] = 1
	r.c.files[of.id] = of
	return r, r.c.sessions[1], of
}

func sessionIntact(t *testing.T, r *requester, alice *session, of *openFile) {
	t.Helper()
	if r.c.sessions[1] != alice || alice.user != "alice" {
		t.Errorf("HIJACK: session 1 is %v, user %q; it was alice's", r.c.sessions[1] != alice, r.c.sessions[1].user)
	}
	if r.c.trees[5] == nil || r.c.trees[5].session != 1 || r.c.files[of.id] != of {
		t.Error("the session's tree or handle was disturbed")
	}
}

func TestAnUnsignedSessionSetupCannotTakeOverASession(t *testing.T) {
	r, alice, of := reauthConn(t)
	c := r.c
	// Leg one, unsigned, naming alice's live session.
	out, err := c.dispatchChain(r.setup(1, ntlmType1(), false))
	if err != nil {
		t.Fatal(err)
	}
	if st := statusOf(t, out); st != statusAccessDenied {
		t.Errorf("an unsigned SESSION_SETUP on a live session answered %#x, want ACCESS_DENIED", st)
	}
	// Whatever a client does with a challenge it was never given.
	if c.pending != nil {
		t.Error("a challenge was issued for the unsigned request")
	}
	out, _ = c.dispatchChain(r.setup(1, ntlmType3(&challenge{}, "mallory", "pw"), false))
	if st := statusOf(t, out); st == statusSuccess {
		t.Errorf("an unsigned authentication on a live session succeeded")
	}
	sessionIntact(t, r, alice, of)
}

// The same, signed with a session key the attacker does not have: the signature
// is wrong, and the request never reaches the handler.
func TestASessionSetupSignedWithTheWrongKeyIsRefused(t *testing.T) {
	r, alice, of := reauthConn(t)
	r.key = []byte("not alice's key.")
	out, _ := r.c.dispatchChain(r.setup(1, ntlmType1(), true))
	if st := statusOf(t, out); st != statusAccessDenied {
		t.Errorf("answered %#x, want ACCESS_DENIED", st)
	}
	sessionIntact(t, r, alice, of)
}

// Authenticating again, signed by the session's own key: allowed for the same
// user, and the session is not replaced; for another user it is refused and the
// session is left exactly as it was.
func TestAReauthenticationMustBeTheSameUser(t *testing.T) {
	for _, tc := range []struct {
		user, password string
		want           uint32
	}{{"alice", "hunter2", statusSuccess}, {"mallory", "pw", statusAccessDenied}} {
		r, alice, of := reauthConn(t)
		c := r.c
		out, err := c.dispatchChain(r.setup(1, ntlmType1(), true))
		if err != nil || statusOf(t, out) != statusMoreProcessing {
			t.Fatalf("%s: the first leg: %v %#x", tc.user, err, statusOf(t, out))
		}
		if c.pending == nil {
			t.Fatalf("%s: no challenge", tc.user)
		}
		out, err = c.dispatchChain(r.setup(1, ntlmType3(c.pending, tc.user, tc.password), true))
		if err != nil {
			t.Fatal(err)
		}
		if st := statusOf(t, out); st != tc.want {
			t.Errorf("%s authenticating again answered %#x, want %#x", tc.user, st, tc.want)
		}
		if tc.want == statusSuccess && !verifyMessage(c.signAlgo(), r.key, out) {
			t.Error("the answer is not signed with the session's key")
		}
		sessionIntact(t, r, alice, of)
		if c.pendingSID != 0 || c.pendingReauth != nil {
			t.Errorf("%s: the exchange left state behind", tc.user)
		}
	}
}

// A client does not choose a session id: an id the server never gave out is
// STATUS_USER_SESSION_DELETED (3.3.5.5), and the server allocates the ids of new
// sessions itself.
func TestAClientCannotChooseASessionId(t *testing.T) {
	r, _, _ := reauthConn(t)
	c := r.c
	for _, sid := range []uint64{77, 2, ^uint64(0)} {
		out, err := c.dispatchChain(r.setup(sid, ntlmType1(), false))
		if err != nil {
			t.Fatal(err)
		}
		if st := statusOf(t, out); st != statusUserSessionDeleted {
			t.Errorf("a made-up session id %d answered %#x, want USER_SESSION_DELETED", sid, st)
		}
		if c.pending != nil {
			t.Errorf("a challenge was issued for the made-up id %d", sid)
		}
	}
	// A new session starts with id 0 and is given one by the server.
	out, err := c.dispatchChain(r.setup(0, ntlmType1(), false))
	if err != nil || statusOf(t, out) != statusMoreProcessing {
		t.Fatalf("a new session: %v %#x", err, statusOf(t, out))
	}
	got := binary.LittleEndian.Uint64(out[offSessionID:])
	if got == 0 || got == 1 || c.sessions[got] != nil {
		t.Errorf("the server gave the new session id %d", got)
	}
	// And its second leg must carry that id: a different one is refused.
	out, _ = c.dispatchChain(r.setup(got+1000, ntlmType3(c.pending, "mallory", "pw"), false))
	if st := statusOf(t, out); st == statusSuccess {
		t.Error("the second leg of a new session succeeded under another id")
	}
	if len(c.sessions) != 1 {
		t.Errorf("%d sessions after the refused exchanges, want alice's alone", len(c.sessions))
	}
}
