package smb

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

// What the review of #66 asked for, each case failing on the code it was written
// against: the FullSessionKey for AES-256, the first-mechanism rule (RFC 4178),
// the expired ticket, the renewal race, and a fuzz target.

func krbConn(t *testing.T, stub *stubAcceptor) *requester {
	t.Helper()
	r := requiringConn(t, dialect302)
	delete(r.c.sessions, 1)
	r.c.srv.Kerberos = stub
	return r
}

// ─── blocker 1: Session.FullSessionKey ───────────────────────────────────────

// [MS-SMB2] 3.3.5.5.3 steps 6 and 11: with 3.1.1 and AES-256-GCM the encryption keys
// derive from the WHOLE GSS key (32 bytes for AES256 Kerberos), not the 16 of
// Session.SessionKey. The client here is the one a Windows machine is: it holds the
// 32-byte key and negotiated AES-256-GCM alone, and derives its keys from it.
func TestAES256EncryptionDerivesFromTheFullKey(t *testing.T) {
	full := make([]byte, 32)
	for i := range full {
		full[i] = byte(i + 1)
	}
	for _, tc := range []struct {
		name   string
		kdk    []byte // what the client derives from
		opened bool
	}{
		{"the whole 32-byte key", full, true},
		// The old code's behaviour, as a control: a client deriving from the first 16
		// bytes is NOT the one the server now answers, so this test can tell them apart.
		{"only its first 16 bytes", full[:16], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newConn(New(), nil)
			c.srv.Kerberos = &stubAcceptor{acc: &Accepted{User: "alice", Key: full}, rep: ticketToken(oidKRB5)}
			// AES-256-GCM is the only cipher this client offers.
			if out, err := c.dispatchChain(negotiateRequest311(ctxPreauth([]uint16{hashIDSHA512}, nil),
				ctxList(ctxEncryption, cipherAES256GCM))); err != nil || statusOf(t, out) != statusSuccess {
				t.Fatalf("negotiate: %v", err)
			}
			if c.cipherID != cipherAES256GCM {
				t.Fatalf("the cipher is %d", c.cipherID)
			}
			setup := sessionSetupRequest(0, negInit(ticketToken(oidKRB5)))
			preauth := preauthExtend(c.preauth, setup)
			out, err := c.dispatchChain(setup)
			if err != nil || statusOf(t, out) != statusSuccess {
				t.Fatalf("session setup: %v %#x", err, statusOf(t, out))
			}
			h, _ := parseHeader(out)

			c2s, err := newCipherAEAD(cipherAES256GCM, kdf(tc.kdk, "SMBC2SCipherKey\x00", string(preauth), 256))
			if err != nil {
				t.Fatal(err)
			}
			s2c, err := newCipherAEAD(cipherAES256GCM, kdf(tc.kdk, "SMBS2CCipherKey\x00", string(preauth), 256))
			if err != nil {
				t.Fatal(err)
			}
			client := &sessionCrypto{enc: c2s, dec: s2c, cipher: cipherAES256GCM}
			m := append(requestOf(cmdEcho, []byte{4, 0, 0, 0}), 0, 0, 0, 0)
			binary.LittleEndian.PutUint64(m[offSessionID:], h.sessionID)
			reply, err := c.dispatchChain(client.seal(h.sessionID, m))
			if !tc.opened {
				if err == nil && len(reply) > 4 && [4]byte(reply[:4]) == transformProtocolID {
					t.Fatal("the server decrypted a frame sealed under a key derived from 16 bytes")
				}
				return
			}
			if err != nil {
				t.Fatalf("the server could not decrypt a frame sealed under the full key: %v", err)
			}
			if _, err := client.open(reply); err != nil {
				t.Fatalf("the client cannot open the answer: %v", err)
			}
		})
	}
}

// Signing, and the 128-bit ciphers, stay on the 16-byte key: a 32-byte key with
// AES-128-GCM derives from its first 16 bytes ([MS-SMB2] 3.3.5.5.3 step 11,
// "Otherwise, Session.SessionKey").
func TestAES128EncryptionAndSigningStayOnTheFirst16Bytes(t *testing.T) {
	full := bytes.Repeat([]byte{5}, 16)
	full = append(full, bytes.Repeat([]byte{6}, 16)...)
	c := &conn{srv: New(), dialect: dialect311, cipherID: cipherAES128GCM}
	pre := preauthExtend(preauthStart(), []byte("x"))
	enc1, dec1, err := c.deriveCipherKeysFull(full[:16], full, pre)
	if err != nil {
		t.Fatal(err)
	}
	enc2, dec2, err := c.deriveCipherKeys(full[:16], pre)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, enc1.NonceSize())
	if !bytes.Equal(enc1.Seal(nil, nonce, []byte("x"), nil), enc2.Seal(nil, nonce, []byte("x"), nil)) ||
		!bytes.Equal(dec1.Seal(nil, nonce, []byte("x"), nil), dec2.Seal(nil, nonce, []byte("x"), nil)) {
		t.Error("an AES-128 session derived from more than the first 16 bytes")
	}
	// And before 3.1.1 even AES-256-capable keys are not used: the dialect decides.
	c = &conn{srv: New(), dialect: dialect302}
	a, _, _ := c.deriveCipherKeysFull(full[:16], full, nil)
	b, _, _ := c.deriveCipherKeys(full[:16], nil)
	if !bytes.Equal(a.Seal(nil, make([]byte, a.NonceSize()), []byte("x"), nil), b.Seal(nil, make([]byte, b.NonceSize()), []byte("x"), nil)) {
		t.Error("a 3.0.2 session used the full key")
	}
	// The signing key: derived from SessionKey alone, whatever the full key is.
	r := krbConn(t, &stubAcceptor{acc: &Accepted{User: "alice", Key: full}, rep: ticketToken(oidKRB5)})
	out, err := r.c.dispatchChain(r.setup(0, negInit(ticketToken(oidKRB5)), false))
	if err != nil || statusOf(t, out) != statusSuccess {
		t.Fatalf("%v %#x", err, statusOf(t, out))
	}
	if sess := r.c.sessions[r.c.nextID]; !bytes.Equal(sess.sessionKey, full[:16]) {
		t.Errorf("Session.SessionKey is % x", sess.sessionKey)
	}
}

// ─── blocker 2: the first mechanism ─────────────────────────────────────────

// RFC 4178 section 3.2 (c) II: a token whose mechanism is not the initiator's
// preferred one makes the MIC exchange mandatory (section 5), and this server does
// neither: so the token is refused, and the acceptor never even sees it.
func TestAKerberosTokenBehindAnotherFirstMechanismIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mechs [][]byte
	}{
		{"NTLMSSP first, Kerberos second", [][]byte{oidNTLMSSP, oidKRB5}},
		{"NTLMSSP first, MS-KRB5 second", [][]byte{oidNTLMSSP, oidMSKRB5, oidKRB5}},
		{"NTLMSSP alone, with a Kerberos token", [][]byte{oidNTLMSSP}},
		{"no mechanism list at all", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubAcceptor{acc: &Accepted{User: "alice", Key: bytes.Repeat([]byte{7}, 16)}, rep: ticketToken(oidKRB5)}
			r := krbConn(t, stub)
			out, err := r.c.dispatchChain(r.setup(0, negInitMechs(ticketToken(oidKRB5), tc.mechs...), false))
			if err != nil || statusOf(t, out) != statusLogonFailure {
				t.Errorf("answered %v %#x, want LOGON_FAILURE", err, statusOf(t, out))
			}
			if len(r.c.sessions) != 0 {
				t.Error("a session was created")
			}
			if len(stub.seen) != 0 {
				t.Error("the ticket was verified before the mechanism was checked")
			}
		})
	}
	// The controls: a bare token (no list, no MIC to skip) and a list that starts with
	// either Kerberos OID are still accepted.
	for _, wrap := range []func([]byte) []byte{
		func(tok []byte) []byte { return tok },
		func(tok []byte) []byte { return negInitMechs(tok, oidKRB5, oidNTLMSSP) },
		func(tok []byte) []byte { return negInitMechs(tok, oidMSKRB5, oidKRB5, oidNTLMSSP) },
	} {
		r := krbConn(t, &stubAcceptor{acc: &Accepted{User: "alice", Key: bytes.Repeat([]byte{7}, 16)}, rep: ticketToken(oidKRB5)})
		if out, err := r.c.dispatchChain(r.setup(0, wrap(ticketToken(oidKRB5)), false)); err != nil || statusOf(t, out) != statusSuccess {
			t.Errorf("a token that should be accepted: %v %#x", err, statusOf(t, out))
		}
	}
}

// ─── item 5: expiry ─────────────────────────────────────────────────────────

// A ticket that has already run out would make a session that is expired from
// birth; it is refused instead, on a new session and on a renewal, and a renewal's
// refusal leaves the session's end where it was.
func TestAnAlreadyExpiredTicketIsRefused(t *testing.T) {
	past := time.Now().Add(-time.Second)
	r := krbConn(t, &stubAcceptor{acc: &Accepted{User: "alice", Key: bytes.Repeat([]byte{7}, 16), Expires: past}, rep: ticketToken(oidKRB5)})
	out, err := r.c.dispatchChain(r.setup(0, negInit(ticketToken(oidKRB5)), false))
	if err != nil || statusOf(t, out) != statusLogonFailure || len(r.c.sessions) != 0 {
		t.Errorf("a new session on an expired ticket: %v %#x, %d sessions", err, statusOf(t, out), len(r.c.sessions))
	}

	r = requiringConn(t, dialect302)
	end := time.Now().Add(time.Hour)
	r.c.sessions[1].expires = end
	r.c.srv.Kerberos = &stubAcceptor{acc: &Accepted{User: "alice", Key: bytes.Repeat([]byte{1}, 16), Expires: past}, rep: ticketToken(oidKRB5)}
	out, err = r.c.dispatchChain(r.setup(1, negInit(ticketToken(oidKRB5)), true))
	if err != nil || statusOf(t, out) != statusLogonFailure {
		t.Errorf("a renewal on an expired ticket: %v %#x", err, statusOf(t, out))
	}
	if !r.c.sessions[1].expires.Equal(end) {
		t.Error("a refused renewal moved the session's end")
	}
}

// A renewal moves Session.ExpirationTime on one goroutine while every request
// reads it on others (the server answers frames concurrently): under -race this
// is a data race unless both sides take the connection's lock.
func TestARenewalRacesWithRequestsOnTheSameSession(t *testing.T) {
	r := requiringConn(t, dialect302)
	r.c.sessions[1].expires = time.Now().Add(time.Hour)
	r.c.srv.Kerberos = &stubAcceptor{acc: &Accepted{User: "alice", Key: bytes.Repeat([]byte{1}, 16), Expires: time.Now().Add(2 * time.Hour)}, rep: ticketToken(oidKRB5)}
	const n = 40
	var renewals, flushes [][]byte
	for i := 0; i < n; i++ {
		renewals = append(renewals, r.setup(1, negInit(ticketToken(oidMSKRB5)), true))
		flushes = append(flushes, r.signed(cmdFlush, make([]byte, 24)))
	}
	var wg sync.WaitGroup
	for _, frames := range [][][]byte{renewals, flushes} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, m := range frames {
				r.c.dispatchChain(m)
			}
		}()
	}
	wg.Wait()
	if s := r.c.sessions[1]; s == nil || r.c.sessionEnded(s) {
		t.Error("the session ended")
	}
}

// ─── item 6: fuzzing ────────────────────────────────────────────────────────

func krbSeeds() (blobs, reps [][]byte) {
	tok := ticketToken(oidKRB5)
	blobs = [][]byte{
		negInit(tok),
		negInitMechs(tok, oidKRB5, oidNTLMSSP),
		negInitMechs(tok, oidNTLMSSP, oidKRB5),
		negInitMechs(ticketToken(oidMSKRB5), oidMSKRB5),
		negInitMechs(tok),
		tok,
		ticketToken(oidMSKRB5),
		negTokenRespKerberos(oidKRB5, tok),
		negTokenRespChallenge(ntlmNegotiateToken()),
		ntlmNegotiateToken(),
		{0x60, 0x03, 0x06, 0x01, 0x2a},
		{0x60, 0x84, 0xff, 0xff, 0xff, 0xff},
		nil,
	}
	reps = [][]byte{
		ticketToken(oidKRB5),
		ticketToken(oidMSKRB5),
		negTokenRespKerberos(oidKRB5, nil),
		{0x60, 0x80},
		nil,
	}
	return blobs, reps
}

// FuzzKerberosSessionSetup drives the Kerberos leg of a 3.1.1 connection with a
// stub acceptor that approves everything and answers with a fuzzed AP-REP, so the
// SPNEGO parsing (firstMechType, mechTokenOf) and the AP-REP re-framing see
// arbitrary bytes. Whatever arrives: no panic, and a session exists only for a
// token the first-mechanism rule lets through.
//
// Corpus: testdata/fuzz/FuzzKerberosSessionSetup (committed).
func FuzzKerberosSessionSetup(f *testing.F) {
	blobs, reps := krbSeeds()
	for _, b := range blobs {
		for _, r := range reps {
			f.Add(b, r)
		}
	}
	f.Fuzz(func(t *testing.T, blob, rep []byte) {
		if len(blob) > 60000 {
			t.Skip()
		}
		c := &conn{srv: New()}
		c.sessions, c.trees, c.files, c.searches, c.waiting = map[uint64]*session{}, map[uint32]*treeConn{}, map[[16]byte]*openFile{}, map[[16]byte]*search{}, map[uint64]*pendingOp{}
		c.srv.Kerberos = &stubAcceptor{acc: &Accepted{User: "alice", Key: bytes.Repeat([]byte{7}, 32)}, rep: rep}
		if _, err := c.dispatchChain(negotiateRequest311(ctxPreauth([]uint16{hashIDSHA512}, nil))); err != nil {
			t.Fatal(err)
		}
		c.dispatchChain(sessionSetupRequest(0, blob)) // must not panic
		for id, s := range c.sessions {
			if s.user != "alice" {
				t.Fatalf("session %d belongs to %q", id, s.user)
			}
			if m := firstMechType(blob); !isKerberosToken(blob) && !bytes.Equal(m, oidKRB5) && !bytes.Equal(m, oidMSKRB5) {
				t.Fatalf("session %d was created for a token whose first mechanism is % x", id, m)
			}
		}
	})
}

// FuzzFirstMechType: the mechanism it returns, if any, is a slice of the input.
//
// Corpus: testdata/fuzz/FuzzFirstMechType (committed).
func FuzzFirstMechType(f *testing.F) {
	blobs, _ := krbSeeds()
	for _, b := range blobs {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m := firstMechType(b)
		if m == nil {
			return
		}
		if !bytes.Contains(b, m) {
			t.Fatalf("firstMechType returned bytes % x that are not in the input", m)
		}
	})
}
