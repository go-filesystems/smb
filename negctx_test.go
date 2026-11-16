package smb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// The negotiate contexts of 3.1.1, [MS-SMB2] 2.2.3.1 and 3.3.5.4.

// ctxData builds the Data of one request context.
func ctxPreauth(hashes []uint16, salt []byte) outContext {
	d := make([]byte, 4+2*len(hashes)+len(salt))
	putU16(d[0:], uint16(len(hashes)))
	putU16(d[2:], uint16(len(salt)))
	for i, h := range hashes {
		putU16(d[4+2*i:], h)
	}
	copy(d[4+2*len(hashes):], salt)
	return outContext{ctxPreauthIntegrity, d}
}

func ctxList(typ uint16, ids ...uint16) outContext {
	d := make([]byte, 2+2*len(ids))
	putU16(d[0:], uint16(len(ids)))
	for i, id := range ids {
		putU16(d[2+2*i:], id)
	}
	return outContext{typ, d}
}

// negotiateRequest311 is a NEGOTIATE offering 3.1.1 (and 3.0.2) with the given
// contexts.
func negotiateRequest311(ctxs ...outContext) []byte {
	dialects := []uint16{dialect302, dialect311}
	body := make([]byte, 36+2*len(dialects))
	putU16(body[0:], 36)
	putU16(body[2:], uint16(len(dialects)))
	putU16(body[4:], signingEnabled)
	putU32(body[8:], 0x7f)
	for i, d := range dialects {
		putU16(body[36+2*i:], d)
	}
	req := requestOf(cmdNegotiate, body)
	for len(req)%8 != 0 {
		req = append(req, 0)
	}
	putU32(req[headerLen+28:], uint32(len(req)))
	putU16(req[headerLen+32:], uint16(len(ctxs)))
	return appendContexts(req, ctxs)
}

func TestNegotiateContextsAnswered(t *testing.T) {
	salt := bytes.Repeat([]byte{7}, 32)
	req := negotiateRequest311(
		ctxPreauth([]uint16{hashIDSHA512}, salt),
		ctxList(ctxEncryption, 2, 1),
		ctxList(ctxSigning, signIDAESGMAC, signIDAESCMAC),
		outContext{0x0005, []byte("netname\x00")}, // ignored, not refused
	)
	c := &conn{srv: New()}
	resp, err := c.dispatch(req)
	if err != nil {
		t.Fatal(err)
	}
	if st := statusOf(t, resp); st != statusSuccess {
		t.Fatalf("status %#x", st)
	}
	if got := dialectOf(resp); got != dialect311 {
		t.Fatalf("dialect %#04x, want 3.1.1", got)
	}
	body := resp[headerLen:]
	if n := leU16(body[6:]); n != 2 {
		t.Fatalf("%d contexts answered, want 2 (preauth, signing; no encryption yet)", n)
	}
	off := int(binary.LittleEndian.Uint32(body[60:]))
	if off%8 != 0 || off < headerLen+64 {
		t.Fatalf("context offset %d is not an aligned place after the fixed part", off)
	}
	secOff, secLen := int(leU16(body[56:])), int(leU16(body[58:]))
	if off < secOff+secLen {
		t.Fatalf("contexts at %d overlap the security buffer ending at %d", off, secOff+secLen)
	}
	// Preauth: SHA-512, one algorithm, a 32-byte salt that is not the client's.
	if typ := leU16(resp[off:]); typ != ctxPreauthIntegrity {
		t.Fatalf("first context type %#x", typ)
	}
	dl := int(leU16(resp[off+2:]))
	d := resp[off+8 : off+8+dl]
	if leU16(d[0:]) != 1 || leU16(d[4:]) != hashIDSHA512 || leU16(d[2:]) != 32 {
		t.Errorf("preauth answer %x", d)
	}
	if bytes.Equal(d[6:6+32], salt) {
		t.Error("the salt is the client's, not fresh")
	}
	// Signing: exactly the one chosen, GMAC because it was offered first.
	next := (off + 8 + dl + 7) &^ 7
	if typ := leU16(resp[next:]); typ != ctxSigning {
		t.Fatalf("second context type %#x", typ)
	}
	sd := resp[next+8 : next+8+int(leU16(resp[next+2:]))]
	if leU16(sd[0:]) != 1 || leU16(sd[2:]) != signIDAESGMAC {
		t.Errorf("signing answer %x", sd)
	}
	if c.signAlgo() != sigGMAC {
		t.Errorf("the connection signs with %v", c.signAlgo())
	}

	// The chain: H(H(0^64 || request) || response), over the bytes as they are on
	// the wire, which is what the client hashes too.
	h1 := sha512.Sum512(append(make([]byte, 64), req...))
	h2 := sha512.Sum512(append(h1[:], resp...))
	if !bytes.Equal(c.preauth, h2[:]) {
		t.Errorf("preauth hash %x, want %x", c.preauth, h2)
	}
}

func TestNegotiateSigningChoice(t *testing.T) {
	for _, tc := range []struct {
		name    string
		offered []outContext
		want    sigAlgo
	}{
		{"no signing context: AES-CMAC", nil, sigCMAC},
		{"CMAC only", []outContext{ctxList(ctxSigning, signIDAESCMAC)}, sigCMAC},
		{"GMAC offered", []outContext{ctxList(ctxSigning, signIDAESCMAC, signIDAESGMAC)}, sigGMAC},
		{"only HMAC-SHA256, which 3.x does not use: AES-CMAC", []outContext{ctxList(ctxSigning, signIDHMACSHA256)}, sigCMAC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &conn{srv: New()}
			ctxs := append([]outContext{ctxPreauth([]uint16{hashIDSHA512}, nil)}, tc.offered...)
			resp, err := c.dispatch(negotiateRequest311(ctxs...))
			if err != nil || statusOf(t, resp) != statusSuccess {
				t.Fatalf("%v %#x", err, statusOf(t, resp))
			}
			if c.signAlgo() != tc.want {
				t.Errorf("signs with %v, want %v", c.signAlgo(), tc.want)
			}
			// With no SIGNING context in the request there is none in the answer.
			wantCtx := 1
			if len(tc.offered) > 0 {
				wantCtx = 2
			}
			if n := int(leU16(resp[headerLen+6:])); n != wantCtx {
				t.Errorf("%d contexts answered, want %d", n, wantCtx)
			}
		})
	}
}

// Every rule of 3.3.5.4 that fails the request, and the status it fails with.
func TestNegotiateContextRules(t *testing.T) {
	good := ctxPreauth([]uint16{hashIDSHA512}, nil)
	for _, tc := range []struct {
		name string
		ctxs []outContext
		want uint32
	}{
		{"none at all", nil, statusInvalidParameter},
		{"no preauth context", []outContext{ctxList(ctxSigning, 1)}, statusInvalidParameter},
		{"two preauth contexts", []outContext{good, good}, statusInvalidParameter},
		{"two encryption contexts", []outContext{good, ctxList(ctxEncryption, 1), ctxList(ctxEncryption, 1)}, statusInvalidParameter},
		{"two signing contexts", []outContext{good, ctxList(ctxSigning, 1), ctxList(ctxSigning, 1)}, statusInvalidParameter},
		{"two compression contexts", []outContext{good, {ctxCompression, make([]byte, 8)}, {ctxCompression, make([]byte, 8)}}, statusInvalidParameter},
		{"two RDMA contexts", []outContext{good, {ctxRDMATransform, make([]byte, 8)}, {ctxRDMATransform, make([]byte, 8)}}, statusInvalidParameter},
		{"a preauth context shorter than its structure", []outContext{{ctxPreauthIntegrity, []byte{1, 0}}}, statusInvalidParameter},
		{"a hash count the data cannot hold", []outContext{{ctxPreauthIntegrity, []byte{9, 0, 0, 0, 1, 0}}}, statusInvalidParameter},
		{"a signing list of zero", []outContext{good, {ctxSigning, []byte{0, 0}}}, statusInvalidParameter},
		{"a signing count the data cannot hold", []outContext{good, {ctxSigning, []byte{5, 0, 1, 0}}}, statusInvalidParameter},
		{"a signing context shorter than its structure", []outContext{good, {ctxSigning, []byte{1}}}, statusInvalidParameter},
		{"no hash in common", []outContext{ctxPreauth([]uint16{0x0002}, nil)}, statusNoPreauthHashOverlap},
		// HashAlgorithmCount MUST be greater than zero (2.2.3.1.1): an empty list is
		// malformed, which is not a list that names nothing this server speaks.
		{"an empty hash list", []outContext{ctxPreauth(nil, nil)}, statusInvalidParameter},
		{"unknown contexts are ignored", []outContext{good, {0x7777, []byte{1, 2, 3}}}, statusSuccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &conn{srv: New()}
			resp, err := c.dispatch(negotiateRequest311(tc.ctxs...))
			if err != nil {
				t.Fatal(err)
			}
			if st := statusOf(t, resp); st != tc.want {
				t.Errorf("status %#x, want %#x", st, tc.want)
			}
		})
	}
}

// A context list that lies about where it is, or how much of it there is, is
// refused rather than read past the message.
func TestNegotiateContextListBounds(t *testing.T) {
	base := negotiateRequest311(ctxPreauth([]uint16{hashIDSHA512}, nil))
	mutate := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), base...)) }
	for name, req := range map[string][]byte{
		"offset beyond the message":      mutate(func(b []byte) []byte { putU32(b[headerLen+28:], uint32(len(b)+64)); return b }),
		"offset inside the fixed part":   mutate(func(b []byte) []byte { putU32(b[headerLen+28:], 72); return b }),
		"offset not aligned":             mutate(func(b []byte) []byte { putU32(b[headerLen+28:], uint32(len(b)-7)); return b }),
		"zero contexts":                  mutate(func(b []byte) []byte { putU16(b[headerLen+32:], 0); return b }),
		"more contexts than the message": mutate(func(b []byte) []byte { putU16(b[headerLen+32:], 5); return b }),
		"absurd count":                   mutate(func(b []byte) []byte { putU16(b[headerLen+32:], 0xffff); return b }),
		"a context longer than the rest": mutate(func(b []byte) []byte { putU16(b[len(b)-(8+6)+2:], 0x4000); return b }),
		"a truncated context header":     base[:len(base)-10],
	} {
		t.Run(name, func(t *testing.T) {
			c := &conn{srv: New()}
			resp, err := c.dispatch(req)
			if err != nil {
				t.Fatal(err)
			}
			if st := statusOf(t, resp); st != statusInvalidParameter {
				t.Errorf("status %#x, want INVALID_PARAMETER", st)
			}
		})
	}
}

func TestNegotiateOtherRules(t *testing.T) {
	// A signed NEGOTIATE, and a NEGOTIATE offering no dialect, are refused
	// (3.3.5.2.4 and 3.3.5.4).
	c := &conn{srv: New()}
	req := negotiateRequest(dialect302)
	putU32(req[offFlags:], flagSigned)
	if st := statusOf(t, mustDispatchRaw(t, c, req)); st != statusInvalidParameter {
		t.Errorf("a signed NEGOTIATE answered %#x", st)
	}
	if st := statusOf(t, mustDispatchRaw(t, c, negotiateRequest())); st != statusInvalidParameter {
		t.Errorf("a NEGOTIATE with no dialect answered %#x", st)
	}
	// A second NEGOTIATE ends the connection, without a reply.
	if _, err := c.dispatch(negotiateRequest(dialect302)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.dispatch(negotiateRequest(dialect302)); err == nil {
		t.Error("a second NEGOTIATE was answered")
	}
}

func mustDispatchRaw(t *testing.T, c *conn, req []byte) []byte {
	t.Helper()
	out, err := c.dispatch(req)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// FSCTL_VALIDATE_NEGOTIATE_INFO on a 3.1.1 connection ends it (3.3.5.15.12):
// the pre-authentication hash has done that job.
func TestValidateNegotiateEndsA311Connection(t *testing.T) {
	c := &conn{srv: New(), dialect: dialect311}
	body := make([]byte, 56)
	putU32(body[4:], fsctlValidateNegotiateInfo)
	if _, err := c.dispatch(request(cmdIoctl, 0, body)); err == nil {
		t.Error("VALIDATE_NEGOTIATE_INFO was answered on 3.1.1")
	}
}

// ─── the signing key and AES-GMAC ────────────────────────────────────────────

// 3.1.1 derives the signing key from the preauth hash with label
// "SMBSigningKey" (3.3.5.5.3 step 7); 3.0 with "SMB2AESCMAC" and "SmbSign".
func TestSigningKeyOn311DependsOnThePreauthHash(t *testing.T) {
	sk := []byte("0123456789abcdef")
	h1 := preauthExtend(preauthStart(), []byte("one"))
	h2 := preauthExtend(preauthStart(), []byte("two"))
	k1, k2 := signingKeyFor(dialect311, sk, h1), signingKeyFor(dialect311, sk, h2)
	if bytes.Equal(k1, k2) {
		t.Error("two different negotiate exchanges derived the same signing key")
	}
	if bytes.Equal(k1, signingKeyFor(dialect302, sk, h1)) {
		t.Error("3.1.1 and 3.0.2 derived the same key")
	}
	if len(k1) != 16 {
		t.Errorf("signing key of %d bytes", len(k1))
	}
	if !bytes.Equal(k1, kdf(sk, "SMBSigningKey\x00", string(h1), 128)) {
		t.Error("the 3.1.1 key is not KDF(label SMBSigningKey, context preauth hash)")
	}
	// L = 256 asks for 32 bytes, and the first 16 are NOT the 128-bit key: L is
	// part of the PRF input.
	long := kdf(sk, "SMBSigningKey\x00", string(h1), 256)
	if len(long) != 32 || bytes.Equal(long[:16], k1) {
		t.Errorf("a 256-bit derivation: %x", long)
	}
}

// The nonce of AES-GMAC is the MessageId and then a flag word: bit 0 for a
// server, bit 1 for a CANCEL request (3.1.4.1).
func TestGMACNonce(t *testing.T) {
	mk := func(id uint64, cmd command, flags uint32) []byte {
		b := make([]byte, headerLen)
		binary.LittleEndian.PutUint64(b[offMessageID:], id)
		binary.LittleEndian.PutUint16(b[offCommand:], uint16(cmd))
		binary.LittleEndian.PutUint32(b[offFlags:], flags)
		return b
	}
	for _, tc := range []struct {
		name string
		msg  []byte
		want string
	}{
		{"client request", mk(0x0102030405060708, cmdRead, 0), "080706050403020100000000"},
		{"server response", mk(5, cmdRead, flagServerToRedir), "050000000000000001000000"},
		{"client CANCEL", mk(5, cmdCancel, 0), "050000000000000002000000"},
		{"server answer to a cancelled request", mk(5, cmdCancel, flagServerToRedir), "050000000000000001000000"},
	} {
		if got := hex.EncodeToString(gmacNonce(tc.msg)); got != tc.want {
			t.Errorf("%s: nonce %s, want %s", tc.name, got, tc.want)
		}
	}
}

// ghash and gmacRef are AES-GMAC written out from NIST SP 800-38D without
// crypto/cipher's GCM, so the test compares two constructions and not a
// function with itself. The bit-by-bit multiplication of GF(2^128) is the
// definition in the standard's section 6.3.
func gfMul(x, y [16]byte) [16]byte {
	var z, v [16]byte
	v = y
	for i := 0; i < 128; i++ {
		if x[i/8]&(0x80>>(i%8)) != 0 {
			for j := range z {
				z[j] ^= v[j]
			}
		}
		lsb := v[15] & 1
		for j := 15; j > 0; j-- {
			v[j] = v[j]>>1 | v[j-1]<<7
		}
		v[0] >>= 1
		if lsb != 0 {
			v[0] ^= 0xe1
		}
	}
	return z
}

// gcmRef is AES-GCM with a 96-bit IV, written out from SP 800-38D: CTR from
// inc32(J0) for the ciphertext, GHASH over the padded AAD and ciphertext and
// their lengths, the tag E(J0) xor GHASH. GMAC is the case of no plaintext.
func gcmRef(key, iv, aad, pt []byte) (ct, tag []byte) {
	blk, _ := aes.NewCipher(key)
	var h [16]byte
	blk.Encrypt(h[:], make([]byte, 16))
	j0 := append(append([]byte(nil), iv...), 0, 0, 0, 1)
	ct = make([]byte, len(pt))
	ctr := append([]byte(nil), j0...)
	for i := 0; i < len(pt); i += 16 {
		binary.BigEndian.PutUint32(ctr[12:], binary.BigEndian.Uint32(ctr[12:])+1)
		var ks [16]byte
		blk.Encrypt(ks[:], ctr)
		for j := 0; j < 16 && i+j < len(pt); j++ {
			ct[i+j] = pt[i+j] ^ ks[j]
		}
	}
	var y [16]byte
	absorb := func(data []byte) {
		for i := 0; i < len(data); i += 16 {
			var b [16]byte
			copy(b[:], data[i:min(i+16, len(data))])
			for j := range y {
				y[j] ^= b[j]
			}
			y = gfMul(y, h)
		}
	}
	absorb(aad)
	absorb(ct)
	var lens [16]byte
	binary.BigEndian.PutUint64(lens[0:], uint64(len(aad))*8)
	binary.BigEndian.PutUint64(lens[8:], uint64(len(ct))*8)
	absorb(lens[:])
	var ek [16]byte
	blk.Encrypt(ek[:], j0)
	tag = make([]byte, 16)
	for i := range tag {
		tag[i] = ek[i] ^ y[i]
	}
	return ct, tag
}

func gmacRef(key, iv, aad []byte) []byte {
	_, tag := gcmRef(key, iv, aad, nil)
	return tag
}

// McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)", test case 4: a
// key, a 96-bit IV, 60 bytes of plaintext AND 20 bytes of additional data -- so
// the GHASH multiplication is checked against a published value, which the
// empty-AAD case 1 never reaches.
func TestGCMReferenceAgainstPublishedCase4(t *testing.T) {
	key := unhex(t, "feffe9928665731c6d6a8f9467308308")
	iv := unhex(t, "cafebabefacedbaddecaf888")
	pt := unhex(t, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	aad := unhex(t, "feedfacedeadbeeffeedfacedeadbeefabaddad2")
	wantCT := unhex(t, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
	wantTag := unhex(t, "5bc94fbc3221a5db94fae95ae7121a47")
	ct, tag := gcmRef(key, iv, aad, pt)
	if !bytes.Equal(ct, wantCT) || !bytes.Equal(tag, wantTag) {
		t.Fatalf("the reference disagrees with the published case:\nct  %x\ntag %x", ct, tag)
	}
	// The same case through crypto/cipher, which is what the server runs.
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	if got := g.Seal(nil, iv, pt, aad); !bytes.Equal(got, append(append([]byte(nil), wantCT...), wantTag...)) {
		t.Errorf("crypto/cipher: %x", got)
	}
}

func TestGMACAgainstTheDefinition(t *testing.T) {
	// McGrew & Viega, "The Galois/Counter Mode of Operation", test case 1: a zero
	// key and nonce, no plaintext, no AAD. The tag is the one published there.
	zero := make([]byte, 16)
	want, _ := hex.DecodeString("58e2fccefa7e3061367f1d57a4e7455a")
	if got := gmacSum(zero, make([]byte, 12), nil); !bytes.Equal(got, want) {
		t.Errorf("test case 1: %x, want %x", got, want)
	}
	if got := gmacRef(zero, make([]byte, 12), nil); !bytes.Equal(got, want) {
		t.Fatalf("the reference construction disagrees with the published vector: %x", got)
	}
	// And the reference agrees with the implementation on AADs of every length
	// around the block boundaries, with a nonce built the way SMB builds one.
	key := []byte("0123456789abcdef")
	for n := 0; n < 200; n += 7 {
		msg := bytes.Repeat([]byte{byte(n)}, n)
		nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 0, 0, 0}
		if got, ref := gmacSum(key, nonce, msg), gmacRef(key, nonce, msg); !bytes.Equal(got, ref) {
			t.Fatalf("AAD of %d bytes: %x, reference %x", n, got, ref)
		}
	}
}

// A whole message signed with GMAC verifies from the bytes alone, by the nonce
// they carry, and one byte of change or the other direction does not.
func TestGMACSignsAMessageFromItsOwnBytes(t *testing.T) {
	key := []byte("0123456789abcdef")
	reply := append(responseTo(header{command: cmdEcho, messageID: 41}, statusSuccess), 4, 0, 0, 0)
	signMessage(sigGMAC, key, reply)
	if !verifyMessage(sigGMAC, key, reply) {
		t.Fatal("a GMAC signature did not verify")
	}
	// A server reply is not a client request with the same MessageId: the
	// direction is in the nonce, so a reflected message is refused.
	reflected := append([]byte(nil), reply...)
	binary.LittleEndian.PutUint32(reflected[offFlags:], flagSigned) // the direction bit cleared
	if verifyMessage(sigGMAC, key, reflected) {
		t.Error("a reflected message verified")
	}
	// And a GMAC signature is not a CMAC one.
	if verifyMessage(sigCMAC, key, reply) {
		t.Error("a GMAC signature verified as AES-CMAC")
	}
}
