package smb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// The parts of the Kerberos path a client library cannot reach: what the server
// offers, the shape of its answers, session expiry and re-authentication
// ([MS-SMB2] 3.3.5.2.9, 3.3.5.5.3 step 15, 3.3.5.5).

// stubAcceptor answers as told, and remembers what it was handed.
type stubAcceptor struct {
	acc  *Accepted
	rep  []byte
	err  error
	seen [][]byte
}

func (s *stubAcceptor) Accept(tok []byte) (*Accepted, []byte, error) {
	s.seen = append(s.seen, bytes.Clone(tok))
	if s.err != nil {
		return nil, nil, s.err
	}
	a := *s.acc
	a.Key = bytes.Clone(s.acc.Key)
	return &a, s.rep, nil
}

// ticketToken is a GSS-API Kerberos token with the given mechanism OID and a body
// the stub does not read.
func ticketToken(oid []byte) []byte { return withMech([]byte{0x01, 0x00, 0xff}, oid) }

// negInit wraps a mechanism token the way a client's first SESSION_SETUP does.
func negInit(tok []byte) []byte { return negInitMechs(tok, oidMSKRB5, oidKRB5) }

// negInitMechs is the same with the mechanisms the client lists, in its order.
func negInitMechs(tok []byte, mechs ...[]byte) []byte {
	var list []byte
	for _, m := range mechs {
		list = append(list, derOID(m)...)
	}
	init := derCtx(0, derSeq(append(derCtx(0, derSeq(list)), derCtx(2, derOctet(tok))...)))
	return derApp(0, append(derOID(oidSPNEGO), init...))
}

func securityBuffer(t *testing.T, out []byte) []byte {
	t.Helper()
	body := out[headerLen:]
	off, n := int(binary.LittleEndian.Uint16(body[4:])), int(binary.LittleEndian.Uint16(body[6:]))
	if off < headerLen || off-headerLen+n > len(body) {
		t.Fatalf("a security buffer of %d at %d outside a body of %d", n, off, len(body))
	}
	return body[off-headerLen : off-headerLen+n]
}

func TestTheOfferListsKerberosFirstAndNTLMOnlyWhenAllowed(t *testing.T) {
	both := negTokenInit(true, true)
	i, j, k := bytes.Index(both, oidMSKRB5), bytes.Index(both, oidKRB5), bytes.Index(both, oidNTLMSSP)
	if !(0 < i && i < j && j < k) {
		t.Errorf("MS-KRB5 at %d, Kerberos at %d, NTLMSSP at %d: want that order", i, j, k)
	}
	if bytes.Contains(negTokenInit(true, false), oidNTLMSSP) {
		t.Error("NTLMSSP offered with NTLM disabled")
	}
	if bytes.Contains(negTokenInit(false, true), oidKRB5) || bytes.Contains(negTokenInit(false, true), oidMSKRB5) {
		t.Error("Kerberos offered with no acceptor")
	}
	if !bytes.Equal(negTokenInit(false, true), negTokenInitNTLM()) {
		t.Error("the NTLM-only offer changed")
	}
}

func TestKerberosTokensAreToldFromNTLMOnes(t *testing.T) {
	if isKerberosToken(ntlmType1()) || isKerberosToken(nil) || isKerberosToken([]byte{0x60}) {
		t.Error("something that is not a Kerberos token was taken for one")
	}
	for _, oid := range [][]byte{oidKRB5, oidMSKRB5} {
		tok := ticketToken(oid)
		if !isKerberosToken(tok) {
			t.Errorf("a token with OID % x was not recognised", oid)
		}
		got, _, ok := krbToken(tok)
		if !ok || !bytes.Equal(got, oid) {
			t.Errorf("krbToken gave % x, %v", got, ok)
		}
		// Inside SPNEGO, and bare, mechTokenOf finds the same token.
		if inner, wrapped, err := mechTokenOf(negInit(tok)); err != nil || !wrapped || !bytes.Equal(inner, tok) {
			t.Errorf("SPNEGO: %v, wrapped=%v", err, wrapped)
		}
		if inner, wrapped, err := mechTokenOf(tok); err != nil || wrapped || !bytes.Equal(inner, tok) {
			t.Errorf("bare: %v, wrapped=%v", err, wrapped)
		}
	}
	if isKerberosToken(withMech([]byte{1, 0}, oidNTLMSSP)) {
		t.Error("a token with another OID was taken for Kerberos")
	}
}

// The acceptor is handed the standard OID whichever one the client used, and the
// reply carries the AP-REP in the client's OID.
func TestTheAcceptorSeesTheStandardOIDAndTheClientGetsItsOwn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		oid     []byte
		wrapped bool
	}{{"MS-KRB5 in SPNEGO", oidMSKRB5, true}, {"Kerberos in SPNEGO", oidKRB5, true}, {"Kerberos bare", oidKRB5, false}} {
		// A Windows client lists MS-KRB5 first and frames its token with the
		// standard OID: the answer names the FIRST mechanism, the one the token is
		// for, not the token's framing (see TestTheAnswerNamesTheClientsFirstMechanism).
		t.Run(tc.name, func(t *testing.T) {
			r := requiringConn(t, dialect302)
			delete(r.c.sessions, 1)
			stub := &stubAcceptor{acc: &Accepted{User: "alice", Key: bytes.Repeat([]byte{7}, 32)}, rep: ticketToken(oidKRB5)}
			r.c.srv.Kerberos = stub
			tok := ticketToken(tc.oid)
			if tc.wrapped {
				tok = negInit(tok)
			}
			out, err := r.c.dispatchChain(r.setup(0, tok, false))
			if err != nil || statusOf(t, out) != statusSuccess {
				t.Fatalf("%v %#x", err, statusOf(t, out))
			}
			if _, _, ok := krbToken(stub.seen[0]); !ok || !bytes.HasPrefix(stub.seen[0], ticketToken(oidKRB5)[:len(ticketToken(oidKRB5))]) {
				t.Errorf("the acceptor was handed % x", stub.seen[0])
			}
			sec := securityBuffer(t, out)
			want := ticketToken(tc.oid)
			if tc.wrapped {
				if !bytes.Contains(sec, want) || !bytes.Contains(sec, derCtx(0, derEnum(0))) {
					t.Errorf("the SPNEGO answer does not hold the AP-REP in the client's OID, accept-completed: % x", sec)
				}
				if !bytes.Contains(sec, derCtx(1, derOID(oidMSKRB5))) {
					t.Error("the answer does not name the client's first mechanism (MS-KRB5)")
				}
			} else if !bytes.Equal(sec, want) {
				t.Errorf("a bare client got % x, want % x", sec, want)
			}
			sess := r.c.sessions[r.c.nextID]
			if sess == nil || sess.user != "alice" || !bytes.Equal(sess.sessionKey, bytes.Repeat([]byte{7}, 16)) {
				t.Fatalf("the session is %+v: want alice keyed by the first 16 bytes of the context key", sess)
			}
			if !verifyMessage(r.c.signAlgo(), sess.signingKey, out) {
				t.Error("the final response is not signed with the session's key")
			}
		})
	}
}

// A short key is zero-padded to 16 bytes, as the specification has it.
func TestSessionKeyIsFirst16BytesZeroPadded(t *testing.T) {
	long := sessionKey16(bytes.Repeat([]byte{9}, 32))
	short := sessionKey16([]byte{1, 2, 3})
	if len(long) != 16 || !bytes.Equal(long, bytes.Repeat([]byte{9}, 16)) {
		t.Errorf("long: % x", long)
	}
	if !bytes.Equal(short, append([]byte{1, 2, 3}, make([]byte, 13)...)) {
		t.Errorf("short: % x", short)
	}
}

// Every way the acceptor can say no is the same logon failure and leaves no
// session behind; so is a Kerberos token when there is no acceptor at all.
func TestKerberosRefusalsAreLogonFailures(t *testing.T) {
	good := &Accepted{User: "alice", Key: bytes.Repeat([]byte{1}, 16)}
	for _, tc := range []struct {
		name string
		stub *stubAcceptor
	}{
		{"the acceptor refuses", &stubAcceptor{err: errors.New("replay")}},
		{"no user", &stubAcceptor{acc: &Accepted{Key: good.Key}}},
		{"no key", &stubAcceptor{acc: &Accepted{User: "alice"}}},
		{"no acceptor", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := requiringConn(t, dialect302)
			delete(r.c.sessions, 1)
			if tc.stub != nil {
				r.c.srv.Kerberos = tc.stub
			}
			out, err := r.c.dispatchChain(r.setup(0, negInit(ticketToken(oidMSKRB5)), false))
			if err != nil || statusOf(t, out) != statusLogonFailure {
				t.Errorf("answered %v %#x, want LOGON_FAILURE", err, statusOf(t, out))
			}
			if len(r.c.sessions) != 0 {
				t.Error("a session was created")
			}
		})
	}
}

// NTLMSSP on a server with NTLM disabled: refused whether it is wrapped or bare.
func TestNTLMIsRefusedWhenDisabled(t *testing.T) {
	r := requiringConn(t, dialect302)
	delete(r.c.sessions, 1)
	r.c.srv.DisableNTLM = true
	r.c.srv.Kerberos = &stubAcceptor{err: errors.New("unused")}
	for _, tok := range [][]byte{ntlmType1(), negInit(ntlmType1())} {
		out, err := r.c.dispatchChain(r.setup(0, tok, false))
		if err != nil || statusOf(t, out) != statusLogonFailure {
			t.Errorf("answered %v %#x, want LOGON_FAILURE", err, statusOf(t, out))
		}
		if len(r.c.exchanges) != 0 {
			t.Error("a challenge was issued")
		}
	}
}

// A session ends with its ticket: everything but LOGOFF, CLOSE and LOCK answers
// STATUS_NETWORK_SESSION_EXPIRED ([MS-SMB2] 3.3.5.2.9), and re-authenticating
// as the same user, signed, moves the end ([MS-SMB2] 3.3.5.5).
func TestASessionExpiresWithItsTicketAndCanBeRenewed(t *testing.T) {
	r := requiringConn(t, dialect302)
	r.c.sessions[1].expires = time.Now().Add(-time.Second)
	for _, cmd := range []command{cmdTreeConnect, cmdCreate, cmdRead, cmdWrite, cmdFlush, cmdIoctl, cmdQueryDirectory, cmdQueryInfo, cmdSetInfo} {
		out, err := r.c.dispatchChain(r.signed(cmd, make([]byte, 64)))
		if err != nil || statusOf(t, out) != statusSessionExpired {
			t.Errorf("%v on an expired session answered %v %#x, want SESSION_EXPIRED", cmd, err, statusOf(t, out))
		}
	}
	for _, cmd := range []command{cmdClose, cmdLock} {
		out, _ := r.c.dispatchChain(r.signed(cmd, make([]byte, 64)))
		if out != nil && statusOf(t, out) == statusSessionExpired {
			t.Errorf("%v was refused as expired; the specification has it processed", cmd)
		}
	}

	// Renewal: the same user, signed with the session's key.
	stub := &stubAcceptor{acc: &Accepted{User: "alice", Key: bytes.Repeat([]byte{1}, 16), Expires: time.Now().Add(time.Hour)}, rep: ticketToken(oidKRB5)}
	r.c.srv.Kerberos = stub
	out, err := r.c.dispatchChain(r.setup(1, negInit(ticketToken(oidMSKRB5)), true))
	if err != nil || statusOf(t, out) != statusSuccess {
		t.Fatalf("renewal answered %v %#x", err, statusOf(t, out))
	}
	if !verifyMessage(r.c.signAlgo(), r.key, out) {
		t.Error("the renewal answer is not signed with the session's key")
	}
	if s := r.c.sessions[1]; s.expires.Before(time.Now().Add(30 * time.Minute)) {
		t.Error("the session's end did not move")
	}
	out, _ = r.c.dispatchChain(r.signed(cmdFlush, make([]byte, 64)))
	if statusOf(t, out) == statusSessionExpired {
		t.Error("still expired after renewing")
	}

	// Another user, or unsigned: refused, and the session is untouched.
	stub.acc = &Accepted{User: "mallory", Key: bytes.Repeat([]byte{1}, 16), Expires: time.Now().Add(100 * time.Hour)}
	out, _ = r.c.dispatchChain(r.setup(1, negInit(ticketToken(oidMSKRB5)), true))
	if st := statusOf(t, out); st != statusAccessDenied {
		t.Errorf("another user renewing answered %#x, want ACCESS_DENIED", st)
	}
	out, _ = r.c.dispatchChain(r.setup(1, negInit(ticketToken(oidMSKRB5)), false))
	if st := statusOf(t, out); st != statusAccessDenied {
		t.Errorf("an unsigned renewal answered %#x, want ACCESS_DENIED", st)
	}
	if s := r.c.sessions[1]; s.user != "alice" || s.expires.After(time.Now().Add(2*time.Hour)) {
		t.Errorf("the session was changed: %+v", s)
	}
}

// A zero Expires is no end, which is what an NTLM session has.
func TestAZeroExpiryNeverExpires(t *testing.T) {
	r := requiringConn(t, dialect302)
	out, _ := r.c.dispatchChain(r.signed(cmdFlush, make([]byte, 64)))
	if statusOf(t, out) == statusSessionExpired {
		t.Error("a session with no expiry expired")
	}
}

// ⛔ Measured against Windows 11 (go-authn-kerb-spike, tap.log): the client lists
// MS-KRB5 first, then Kerberos V5, then NTLMSSP, and frames its AP-REQ with the
// STANDARD Kerberos OID. The answer's supportedMech must be the first mechanism
// listed (RFC 4178 section 4.2.1: the optimistic token is for it), not the OID
// the token is framed with: naming another mechanism makes the mechListMIC
// exchange mandatory (section 5), and Windows dropped the connection after the
// SESSION_SETUP response, four times, with "network name cannot be found".
func TestTheAnswerNamesTheClientsFirstMechanism(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mechs [][]byte
		want  []byte
	}{
		{"Windows: MS-KRB5 first, token framed with the standard OID", [][]byte{oidMSKRB5, oidKRB5, oidNTLMSSP}, oidMSKRB5},
		{"Kerberos first", [][]byte{oidKRB5, oidMSKRB5}, oidKRB5},
		// A token under a first mechanism that is not Kerberos: the framing's OID is
		// all there is to name.
		{"NTLMSSP listed first", [][]byte{oidNTLMSSP, oidKRB5}, oidKRB5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := requiringConn(t, dialect302)
			delete(r.c.sessions, 1)
			r.c.srv.Kerberos = &stubAcceptor{acc: &Accepted{User: "alice", Key: bytes.Repeat([]byte{7}, 16)}, rep: ticketToken(oidKRB5)}
			out, err := r.c.dispatchChain(r.setup(0, negInitMechs(ticketToken(oidKRB5), tc.mechs...), false))
			if err != nil || statusOf(t, out) != statusSuccess {
				t.Fatalf("%v %#x", err, statusOf(t, out))
			}
			if sec := securityBuffer(t, out); !bytes.Contains(sec, derCtx(1, derOID(tc.want))) {
				t.Errorf("supportedMech is not % x: % x", tc.want, sec)
			}
		})
	}
	if firstMechType(nil) != nil || firstMechType([]byte{0x60, 0x03, 0x06, 0x01}) != nil || firstMechType(ticketToken(oidKRB5)) != nil {
		t.Error("firstMechType invented a mechanism")
	}
}
