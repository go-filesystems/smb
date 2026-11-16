package smb

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// ─── AES-CCM ─────────────────────────────────────────────────────────────────

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 3610 section 8, Packet Vector #1 (opened 2026-11-16): the standard's own
// vector, with an 8-byte tag and a 13-byte nonce, which is why newCCM takes both
// as parameters.
func TestCCMAgainstRFC3610(t *testing.T) {
	key := unhex(t, "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
	nonce := unhex(t, "00000003020100A0A1A2A3A4A5")
	packet := unhex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E")
	// "Authenticated and Encrypted Output": the 8 header bytes in the clear, then
	// 23 bytes of ciphertext, then the 8-byte tag.
	want := unhex(t, "0001020304050607"+"588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384"+"17E8D12CFDF926E0")
	blk, _ := aes.NewCipher(key)
	a, err := newCCM(blk, 13, 8)
	if err != nil {
		t.Fatal(err)
	}
	header, payload := packet[:8], packet[8:]
	got := append(append([]byte(nil), header...), a.Seal(nil, nonce, payload, header)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("sealed %x\nwant   %x", got, want)
	}
	back, err := a.Open(nil, nonce, got[8:], header)
	if err != nil || !bytes.Equal(back, payload) {
		t.Fatalf("opened %x, %v", back, err)
	}
}

// With SMB's sizes (11-byte nonce, 16-byte tag): every length around the block
// boundaries, with and without additional data, opens to what was sealed, and
// any change to the message, the data, the nonce or the tag is refused.
func TestCCMWithSMBSizes(t *testing.T) {
	blk, _ := aes.NewCipher([]byte("0123456789abcdef"))
	a, err := newCCM(blk, 11, 16)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 11)
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 1000} {
		for _, aadLen := range []int{0, 1, 32, 70000} {
			msg := bytes.Repeat([]byte{byte(n)}, n)
			aad := bytes.Repeat([]byte{7}, aadLen)
			sealed := a.Seal(nil, nonce, msg, aad)
			if len(sealed) != n+16 {
				t.Fatalf("sealed %d bytes for %d", len(sealed), n)
			}
			back, err := a.Open(nil, nonce, sealed, aad)
			if err != nil || !bytes.Equal(back, msg) {
				t.Fatalf("n=%d aad=%d: %v", n, aadLen, err)
			}
			for i := range sealed {
				bad := append([]byte(nil), sealed...)
				bad[i] ^= 1
				if _, err := a.Open(nil, nonce, bad, aad); err == nil {
					t.Fatalf("n=%d aad=%d: a change at byte %d was accepted", n, aadLen, i)
				}
			}
			if _, err := a.Open(nil, nonce, sealed, append([]byte{1}, aad...)); err == nil {
				t.Fatal("changed additional data accepted")
			}
			n2 := append([]byte(nil), nonce...)
			n2[0] = 1
			if _, err := a.Open(nil, n2, sealed, aad); err == nil {
				t.Fatal("another nonce accepted")
			}
		}
	}
	if _, err := a.Open(nil, nonce, make([]byte, 5), nil); err == nil {
		t.Error("a ciphertext shorter than its tag was accepted")
	}
	if _, err := a.Open(nil, nonce[:5], make([]byte, 40), nil); err == nil {
		t.Error("a nonce of the wrong size was accepted")
	}
	for _, bad := range [][2]int{{11, 3}, {11, 17}, {6, 16}, {14, 16}} {
		if _, err := newCCM(blk, bad[0], bad[1]); err == nil {
			t.Errorf("newCCM accepted nonce %d tag %d", bad[0], bad[1])
		}
	}
}

// ─── the TRANSFORM_HEADER ────────────────────────────────────────────────────

// encPair is a server connection with one encrypted session, and the matching
// client end: the client encrypts with the server's DecryptionKey and decrypts
// with its EncryptionKey.
type encPair struct {
	c      *conn
	sess   *session
	client *sessionCrypto
	sid    uint64
}

func newEncPair(t testing.TB, dialect, cipherID uint16) *encPair {
	t.Helper()
	c := newConn(New(), nil)
	c.dialect, c.cipherID, c.clientCapabilities = dialect, cipherID, capEncryption
	pre := preauthExtend(preauthStart(), []byte("x"))
	if dialect != dialect311 {
		pre = nil
	}
	enc, dec, err := c.deriveCipherKeys([]byte("0123456789abcdef"), pre)
	if err != nil {
		t.Fatal(err)
	}
	sess := &session{user: "alice", crypto: &sessionCrypto{enc: enc, dec: dec, cipher: c.sessionCipher()}}
	c.sessions[7] = sess
	return &encPair{c, sess, &sessionCrypto{enc: dec, dec: enc, cipher: sess.crypto.cipher}, 7}
}

var allCiphers = []struct {
	dialect uint16
	cipher  uint16
}{
	{dialect300, cipherNone}, {dialect302, cipherNone},
	{dialect311, cipherAES128CCM}, {dialect311, cipherAES128GCM},
	{dialect311, cipherAES256CCM}, {dialect311, cipherAES256GCM},
}

func TestTransformHeaderLayoutAndRoundTrip(t *testing.T) {
	for _, tc := range allCiphers {
		p := newEncPair(t, tc.dialect, tc.cipher)
		plain := append(requestOf(cmdEcho, []byte{4, 0, 0, 0}), 1, 2, 3)
		binary.LittleEndian.PutUint64(plain[offSessionID:], p.sid)
		frame := p.client.seal(p.sid, plain)
		name := dialectName(tc.dialect) + "/" + cipherName(p.sess.crypto.cipher)
		if [4]byte(frame[:4]) != transformProtocolID {
			t.Fatalf("%s: protocol id %x", name, frame[:4])
		}
		if got := binary.LittleEndian.Uint32(frame[offTrOrigSize:]); int(got) != len(plain) {
			t.Errorf("%s: OriginalMessageSize %d, want %d", name, got, len(plain))
		}
		if f := binary.LittleEndian.Uint16(frame[offTrFlags:]); f != 1 {
			t.Errorf("%s: Flags/EncryptionAlgorithm %d, want 1", name, f)
		}
		if sid := binary.LittleEndian.Uint64(frame[offTrSessionID:]); sid != p.sid {
			t.Errorf("%s: session id %d", name, sid)
		}
		if len(frame) != transformLen+len(plain) {
			t.Errorf("%s: frame of %d bytes for %d of message", name, len(frame), len(plain))
		}
		if bytes.Contains(frame[transformLen:], plain[headerLen:]) {
			t.Errorf("%s: the message is in the clear", name)
		}
		got, err := p.sess.crypto.open(frame)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%s: server opened %x, %v", name, got, err)
		}
		// Every bit of the nonce, the size, the flags, the session id, the tag and
		// the ciphertext is authenticated; the protocol id is not (it is not part of
		// the message, it says which kind of frame this is).
		for i := 4; i < len(frame); i++ {
			bad := append([]byte(nil), frame...)
			bad[i] ^= 0x80
			if i >= offTrNonce+p.sess.crypto.dec.NonceSize() && i < offTrOrigSize {
				continue // the reserved bytes of the nonce field are not used by the cipher
			}
			if _, err := p.sess.crypto.open(bad); err == nil {
				t.Fatalf("%s: a change at byte %d was accepted", name, i)
			}
		}
	}
}

// A nonce is never used twice under one key, whichever direction or thread.
func TestNoncesDoNotRepeat(t *testing.T) {
	p := newEncPair(t, dialect311, cipherAES128GCM)
	seen := map[string]bool{}
	for i := 0; i < 5000; i++ {
		n := string(p.sess.crypto.nonce())
		if seen[n] {
			t.Fatalf("nonce %x repeated after %d", n, i)
		}
		seen[n] = true
	}
}

// The keys: 3.1.1 labels SMBS2CCipherKey (server to client) and SMBC2SCipherKey
// with the preauth hash as context; before it, SMB2AESCCM with ServerOut and
// "ServerIn " ([MS-SMB2] 3.3.5.5.3 step 11). 256-bit ciphers take 32 bytes.
func TestCipherKeyDerivation(t *testing.T) {
	sk := []byte("0123456789abcdef")
	pre := preauthExtend(preauthStart(), []byte("x"))
	c := &conn{srv: New(), dialect: dialect311, cipherID: cipherAES128CCM}
	// Derive the keys the long way and compare what they seal.
	probe := func(c *conn, ek, dk []byte) {
		t.Helper()
		enc, dec, err := c.deriveCipherKeys(sk, pre)
		if err != nil {
			t.Fatal(err)
		}
		wantEnc, _ := newCipherAEAD(c.sessionCipher(), ek)
		wantDec, _ := newCipherAEAD(c.sessionCipher(), dk)
		n := make([]byte, enc.NonceSize())
		if !bytes.Equal(enc.Seal(nil, n, []byte("m"), nil), wantEnc.Seal(nil, n, []byte("m"), nil)) {
			t.Error("EncryptionKey is not the derived server-to-client key")
		}
		if !bytes.Equal(dec.Seal(nil, n, []byte("m"), nil), wantDec.Seal(nil, n, []byte("m"), nil)) {
			t.Error("DecryptionKey is not the derived client-to-server key")
		}
		if bytes.Equal(ek, dk) {
			t.Error("the two directions share a key")
		}
	}
	probe(c, kdf(sk, "SMBS2CCipherKey\x00", string(pre), 128), kdf(sk, "SMBC2SCipherKey\x00", string(pre), 128))
	c.cipherID = cipherAES256GCM
	probe(c, kdf(sk, "SMBS2CCipherKey\x00", string(pre), 256), kdf(sk, "SMBC2SCipherKey\x00", string(pre), 256))
	c = &conn{srv: New(), dialect: dialect302}
	probe(c, kdf(sk, "SMB2AESCCM\x00", "ServerOut\x00", 128), kdf(sk, "SMB2AESCCM\x00", "ServerIn \x00", 128))
}

func TestChooseCipher(t *testing.T) {
	for _, tc := range []struct {
		offered []uint16
		want    uint16
	}{
		{[]uint16{cipherAES128CCM}, cipherAES128CCM},
		{[]uint16{cipherAES128CCM, cipherAES128GCM}, cipherAES128GCM},
		{[]uint16{cipherAES256GCM, cipherAES256CCM}, cipherAES256GCM},
		{[]uint16{cipherAES256GCM, cipherAES128CCM}, cipherAES128CCM},
		{[]uint16{0x0009}, cipherNone},
		{nil, cipherNone},
	} {
		if got := chooseCipher(tc.offered); got != tc.want {
			t.Errorf("offered %v: %d, want %d", tc.offered, got, tc.want)
		}
	}
}

// ─── negotiation ─────────────────────────────────────────────────────────────

func TestNegotiateCipher(t *testing.T) {
	pre := ctxPreauth([]uint16{hashIDSHA512}, nil)
	answer := func(t *testing.T, srv *Server, ctxs ...outContext) (*conn, []byte) {
		t.Helper()
		c := &conn{srv: srv}
		resp, err := c.dispatch(negotiateRequest311(append([]outContext{pre}, ctxs...)...))
		if err != nil || statusOf(t, resp) != statusSuccess {
			t.Fatalf("%v %#x", err, statusOf(t, resp))
		}
		return c, resp
	}
	cipherAnswer := func(resp []byte) (id uint16, present bool) {
		off := int(binary.LittleEndian.Uint32(resp[headerLen+60:]))
		for i := 0; i < int(leU16(resp[headerLen+6:])); i++ {
			dl := int(leU16(resp[off+2:]))
			if leU16(resp[off:]) == ctxEncryption {
				d := resp[off+8 : off+8+dl]
				if leU16(d[0:]) != 1 {
					t.Fatalf("a cipher list of %d", leU16(d[0:]))
				}
				return leU16(d[2:]), true
			}
			off = (off + 8 + dl + 7) &^ 7
		}
		return 0, false
	}

	c, resp := answer(t, New(), ctxList(ctxEncryption, cipherAES128CCM, cipherAES256GCM))
	if id, ok := cipherAnswer(resp); !ok || id != cipherAES128CCM || c.cipherID != cipherAES128CCM {
		t.Errorf("answered %d (%v), connection %d", id, ok, c.cipherID)
	}
	// No cipher in common: the context is still sent, with cipher 0, so the client
	// can tell it from a server that does not encrypt (3.3.5.4).
	c, resp = answer(t, New(), ctxList(ctxEncryption, 0x0042))
	if id, ok := cipherAnswer(resp); !ok || id != 0 || c.encCapable() {
		t.Errorf("no common cipher: answered %d (%v), capable %v", id, ok, c.encCapable())
	}
	// No encryption context in the request, none in the answer.
	if _, resp = answer(t, New()); func() bool { _, ok := cipherAnswer(resp); return ok }() {
		t.Error("an encryption context was answered to a client that sent none")
	}
	// A server that does not offer encryption ignores the context.
	off := New()
	off.DisableEncryption = true
	c, resp = answer(t, off, ctxList(ctxEncryption, cipherAES128GCM))
	if _, ok := cipherAnswer(resp); ok || c.encCapable() {
		t.Error("a server with encryption disabled answered the context")
	}
}

// 3.0 and 3.0.2 negotiate encryption with a capability bit, both ways; 3.1.1 does
// not claim it, because its response table marks the bit invalid (2.2.4).
func TestEncryptionCapabilityBit(t *testing.T) {
	caps := func(dialect uint16, srv *Server, clientCaps uint32) uint32 {
		c := &conn{srv: srv}
		req := negotiateRequest(dialect)
		putU32(req[headerLen+8:], clientCaps)
		resp, err := c.dispatch(req)
		if err != nil || statusOf(t, resp) != statusSuccess {
			t.Fatalf("%v", err)
		}
		return binary.LittleEndian.Uint32(resp[headerLen+24:])
	}
	for _, d := range []uint16{dialect300, dialect302} {
		if caps(d, New(), 0x7f)&capEncryption == 0 {
			t.Errorf("%s: encryption not claimed to a client that has it", dialectName(d))
		}
		if caps(d, New(), 0x3f)&capEncryption != 0 {
			t.Errorf("%s: encryption claimed to a client that does not", dialectName(d))
		}
		off := New()
		off.DisableEncryption = true
		if caps(d, off, 0x7f)&capEncryption != 0 {
			t.Errorf("%s: encryption claimed by a server with it disabled", dialectName(d))
		}
	}
	if caps(dialect210, New(), 0x7f)&capEncryption != 0 {
		t.Error("2.1 claimed encryption")
	}
}

// ─── the frame, end to end through the dispatcher ────────────────────────────

func echoFrame(p *encPair, sid uint64) []byte {
	m := append(requestOf(cmdEcho, []byte{4, 0, 0, 0}), 0, 0, 0, 0)
	binary.LittleEndian.PutUint64(m[offSessionID:], sid)
	return p.client.seal(sid, m)
}

// An encrypted request is answered encrypted, under the server's key and with a
// fresh nonce each time.
func TestAnEncryptedRequestIsAnsweredEncrypted(t *testing.T) {
	for _, tc := range allCiphers {
		p := newEncPair(t, tc.dialect, tc.cipher)
		var nonces [][]byte
		for i := 0; i < 3; i++ {
			reply, err := p.c.dispatchChain(echoFrame(p, p.sid))
			if err != nil {
				t.Fatal(err)
			}
			if [4]byte(reply[:4]) != transformProtocolID {
				t.Fatalf("%s: the answer to an encrypted request is not encrypted", dialectName(tc.dialect))
			}
			plain, err := p.client.open(reply)
			if err != nil {
				t.Fatalf("the client cannot open the answer: %v", err)
			}
			if h, _ := parseHeader(plain); h.command != cmdEcho || h.status != statusSuccess || h.flags&flagSigned != 0 {
				t.Errorf("answer %+v (an encrypted reply is not signed as well)", h)
			}
			nonces = append(nonces, reply[offTrNonce:offTrNonce+16])
		}
		if bytes.Equal(nonces[0], nonces[1]) || bytes.Equal(nonces[1], nonces[2]) {
			t.Error("a nonce was reused")
		}
	}
}

// Every way 3.3.5.2.1.1 says to disconnect.
func TestFramesThatEndTheConnection(t *testing.T) {
	p := newEncPair(t, dialect311, cipherAES128GCM)
	good := echoFrame(p, p.sid)
	mut := func(f func(b []byte)) []byte { b := append([]byte(nil), good...); f(b); return b }
	plainInside := func(plain []byte) []byte { return p.client.seal(p.sid, plain) }
	echo := func(sid uint64, flags uint32) []byte {
		m := append(requestOf(cmdEcho, []byte{4, 0, 0, 0}), 0, 0, 0, 0)
		binary.LittleEndian.PutUint64(m[offSessionID:], sid)
		binary.LittleEndian.PutUint32(m[offFlags:], flags)
		return m
	}
	for name, frame := range map[string][]byte{
		"only a header":               mut(func(b []byte) {})[:transformLen],
		"flags not 1":                 mut(func(b []byte) { b[offTrFlags] = 2 }),
		"an unknown session":          mut(func(b []byte) { b[offTrSessionID] = 99 }),
		"a tag that does not verify":  mut(func(b []byte) { b[offTrSignature] ^= 1 }),
		"a wrong original size":       mut(func(b []byte) { b[offTrOrigSize]++ }),
		"not an SMB2 message inside":  plainInside(bytes.Repeat([]byte{'x'}, 80)),
		"a compressed message inside": plainInside(append([]byte{0xFC, 'S', 'M', 'B'}, make([]byte, 80)...)),
		"a message shorter than SMB2": plainInside([]byte{0xFE, 'S', 'M', 'B', 1}),
		"another session inside":      plainInside(echo(8, 0)),
		"a related first operation":   plainInside(echo(p.sid, flagRelatedOps)),
	} {
		if out, err := p.c.dispatchChain(frame); err == nil {
			t.Errorf("%s: answered (%d bytes) instead of ending the connection", name, len(out))
		}
	}
	// A transform header on a connection that never agreed to encrypt.
	c := newConn(New(), nil)
	c.dialect = dialect302
	if _, err := c.dispatchChain(good); err == nil {
		t.Error("an encrypted frame was accepted on a connection with no session")
	}
	// A session that cannot encrypt.
	p.c.sessions[7] = &session{user: "alice"}
	if _, err := p.c.dispatchChain(good); err == nil {
		t.Error("an encrypted frame was accepted for a session with no keys")
	}
}

// What a session or a share requires ([MS-SMB2] 3.3.5.2.9, 3.3.5.2.11): the
// request that does not come encrypted is refused ACCESS_DENIED, and the refusal
// is encrypted.
func TestEncryptionRequiredIsEnforced(t *testing.T) {
	plainEcho := func(p *encPair) []byte {
		m := append(requestOf(cmdEcho, []byte{4, 0, 0, 0}), 0, 0, 0, 0)
		binary.LittleEndian.PutUint64(m[offSessionID:], p.sid)
		return m
	}
	t.Run("session", func(t *testing.T) {
		p := newEncPair(t, dialect311, cipherAES128GCM)
		out, err := p.c.dispatchChain(plainEcho(p))
		if err != nil || statusOf(t, out) != statusSuccess {
			t.Fatalf("a session that does not require encryption refused a plain request: %v", err)
		}
		p.sess.encryptData = true
		out, err = p.c.dispatchChain(plainEcho(p))
		if err != nil {
			t.Fatal(err)
		}
		if [4]byte(out[:4]) != transformProtocolID {
			t.Fatal("the refusal was sent in the clear")
		}
		plain, err := p.client.open(out)
		if err != nil || statusOf(t, plain) != statusAccessDenied {
			t.Errorf("status %#x, %v", statusOf(t, plain), err)
		}
		// And what does come encrypted works.
		out, err = p.c.dispatchChain(echoFrame(p, p.sid))
		if err != nil {
			t.Fatal(err)
		}
		if plain, _ = p.client.open(out); statusOf(t, plain) != statusSuccess {
			t.Errorf("an encrypted request on an encrypted session answered %#x", statusOf(t, plain))
		}
		// NEGOTIATE and SESSION_SETUP are the commands that come before there is a
		// session to require anything.
		if c := newConn(New(), nil); true {
			if out, _ := c.dispatchChain(negotiateRequest(dialect302)); statusOf(t, out) != statusSuccess {
				t.Error("NEGOTIATE refused")
			}
		}
	})
	t.Run("share", func(t *testing.T) {
		p := newEncPair(t, dialect311, cipherAES128GCM)
		p.c.trees[5] = &treeConn{sh: &share{name: "secret", encrypt: true}}
		p.c.trees[6] = &treeConn{sh: &share{name: "open"}}
		query := func(tree uint32) []byte {
			m := requestOf(cmdFlush, make([]byte, 24))
			binary.LittleEndian.PutUint64(m[offSessionID:], p.sid)
			binary.LittleEndian.PutUint32(m[offTreeID:], tree)
			return m
		}
		// On the plain share a plain request is a request; on the other it is refused.
		if out, _ := p.c.dispatchChain(query(6)); statusOf(t, out) == statusAccessDenied {
			t.Error("a plain request on a plain share was refused")
		}
		out, err := p.c.dispatchChain(query(5))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := p.client.open(out)
		if err != nil || statusOf(t, plain) != statusAccessDenied {
			t.Fatalf("a plain request on an encrypting share: %v, %#x", err, statusOf(t, plain))
		}
		// Encrypted, the same request is dispatched (and fails for a reason of its
		// own: there is no such handle).
		m := query(5)
		out, err = p.c.dispatchChain(p.client.seal(p.sid, m))
		if err != nil {
			t.Fatal(err)
		}
		plain, err = p.client.open(out)
		if err != nil || statusOf(t, plain) == statusAccessDenied {
			t.Errorf("an encrypted request on an encrypting share: %v, %#x", err, statusOf(t, plain))
		}
	})
}

// A LOGOFF inside an encrypted frame is answered encrypted although the session
// is gone by the time the answer is made.
func TestTheAnswerToALogoffIsEncrypted(t *testing.T) {
	p := newEncPair(t, dialect311, cipherAES128CCM)
	m := requestOf(cmdLogoff, []byte{4, 0, 0, 0})
	binary.LittleEndian.PutUint64(m[offSessionID:], p.sid)
	out, err := p.c.dispatchChain(p.client.seal(p.sid, m))
	if err != nil {
		t.Fatal(err)
	}
	if _, gone := p.c.sessions[p.sid]; gone {
		t.Fatal("the session survived its LOGOFF")
	}
	if plain, err := p.client.open(out); err != nil || statusOf(t, plain) != statusSuccess {
		t.Errorf("the LOGOFF answer: %v", err)
	}
}

// A compound of two operations is decrypted as one frame and answered as one.
func TestAnEncryptedCompoundIsAnsweredAsOne(t *testing.T) {
	p := newEncPair(t, dialect311, cipherAES128GCM)
	first := append(requestOf(cmdEcho, []byte{4, 0, 0, 0}), 0, 0, 0, 0)
	binary.LittleEndian.PutUint64(first[offSessionID:], p.sid)
	binary.LittleEndian.PutUint32(first[offNextCommand:], uint32(len(first)))
	second := append(requestOf(cmdEcho, []byte{4, 0, 0, 0}), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(second[offFlags:], flagRelatedOps)
	out, err := p.c.dispatchChain(p.client.seal(p.sid, append(first, second...)))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := p.client.open(out)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := parseHeader(plain)
	if h.nextCommand == 0 || int(h.nextCommand) >= len(plain) {
		t.Fatalf("the first answer does not chain to a second: %d of %d", h.nextCommand, len(plain))
	}
	if h2, err := parseHeader(plain[h.nextCommand:]); err != nil || h2.command != cmdEcho {
		t.Errorf("second answer: %v", err)
	}
}

// Sessions and shares that require encryption refuse a connection that cannot
// do it, at the earliest message where the rule applies.
func TestRequirementsRefuseAClientThatCannotEncrypt(t *testing.T) {
	// Server.EncryptData: SESSION_SETUP is refused on 2.1 and on a 3.x connection
	// with no cipher or capability.
	srv := New()
	srv.EncryptData = true
	for _, tc := range []struct {
		name  string
		build func() *conn
	}{
		{"2.1", func() *conn { return &conn{srv: srv, dialect: dialect210} }},
		{"3.0.2 without the capability", func() *conn { return &conn{srv: srv, dialect: dialect302} }},
		{"3.1.1 without a cipher", func() *conn { return &conn{srv: srv, dialect: dialect311} }},
	} {
		c := tc.build()
		body := make([]byte, 24)
		if st := statusOf(t, mustDispatchRaw(t, c, requestOf(cmdSessionSetup, body))); st != statusAccessDenied {
			t.Errorf("%s: SESSION_SETUP answered %#x, want ACCESS_DENIED", tc.name, st)
		}
	}
	// A share that requires it refuses TREE_CONNECT from such a client.
	c := newConn(New(), nil)
	c.dialect = dialect210
	c.sessions[1] = &session{user: "alice"}
	if err := c.srv.Share("secret", nothingFS{}, RequireEncryption()); err != nil {
		t.Fatal(err)
	}
	path := utf16le(`\\host\secret`)
	body := make([]byte, 8)
	putU16(body[0:], 9)
	putU16(body[4:], headerLen+8)
	putU16(body[6:], uint16(len(path)))
	req := append(requestOf(cmdTreeConnect, body), path...)
	binary.LittleEndian.PutUint64(req[offSessionID:], 1)
	if st := statusOf(t, mustDispatchRaw(t, c, req)); st != statusAccessDenied {
		t.Errorf("TREE_CONNECT answered %#x, want ACCESS_DENIED", st)
	}
	// And one that can gets the flag.
	c.dialect, c.cipherID = dialect311, cipherAES128GCM
	resp := mustDispatchRaw(t, c, req)
	if statusOf(t, resp) != statusSuccess {
		t.Fatalf("TREE_CONNECT answered %#x", statusOf(t, resp))
	}
	if flags := binary.LittleEndian.Uint32(resp[headerLen+4:]); flags&shareFlagEncryptData == 0 {
		t.Errorf("ShareFlags %#x lack SMB2_SHAREFLAG_ENCRYPT_DATA", flags)
	}
}
