package smb

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The two algorithms, chosen by dialect, and the derivation that goes with
// each: 2.x keys HMAC-SHA256 with the session key itself, 3.x keys AES-CMAC
// with a key derived from it.
func TestSigningKeyDependsOnTheDialect(t *testing.T) {
	sessionKey := []byte("0123456789abcdef")
	for _, d := range []uint16{dialect202, dialect210} {
		if got := signingKeyFor(d, sessionKey, nil); !bytes.Equal(got, sessionKey) {
			t.Errorf("dialect %#04x derives a key where it should use the session key", d)
		}
	}
	for _, d := range []uint16{dialect300, dialect302} {
		got := signingKeyFor(d, sessionKey, nil)
		if bytes.Equal(got, sessionKey) {
			t.Errorf("dialect %#04x signs with the session key itself", d)
		}
		if len(got) != 16 {
			t.Errorf("dialect %#04x derived %d bytes", d, len(got))
		}
	}
	// The derivation is a function of its inputs, and a different label gives
	// a different key -- which is what stops a signing key doubling as an
	// encryption key.
	if bytes.Equal(kdf(sessionKey, "SMB2AESCMAC\x00", "SmbSign\x00", 128),
		kdf(sessionKey, "SMB2AESCCM\x00", "ServerIn \x00", 128)) {
		t.Error("two labels derived the same key")
	}
}

// A signature covers the whole message with its own field zeroed, so signing
// and verifying are the same computation from the two sides.
func TestSignAndVerifyRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef")
	for _, d := range []sigAlgo{sigHMAC, sigCMAC, sigGMAC} {
		msg := append(responseTo(header{command: cmdEcho, messageID: 3}, statusSuccess), 1, 2, 3, 4)
		signMessage(d, key, msg)
		if binary.LittleEndian.Uint32(msg[offFlags:])&flagSigned == 0 {
			t.Errorf("dialect %#04x signed without saying so", d)
		}
		if !verifyMessage(d, key, msg) {
			t.Errorf("dialect %#04x did not verify its own signature", d)
		}
		// …and verifying must not have changed the message, or the next
		// reader sees something else.
		if !verifyMessage(d, key, msg) {
			t.Errorf("dialect %#04x verified once and then failed", d)
		}
		// One byte anywhere breaks it.
		for _, at := range []int{offCommand, headerLen, len(msg) - 1} {
			bad := append([]byte(nil), msg...)
			bad[at] ^= 0xFF
			if verifyMessage(d, key, bad) {
				t.Errorf("dialect %#04x accepted a message changed at byte %d", d, at)
			}
		}
		// Another key does not.
		if verifyMessage(d, []byte("fedcba9876543210"), msg) {
			t.Errorf("dialect %#04x accepted a signature under another key", d)
		}
	}
	// Nothing to sign with, or nothing to sign: no signature and no panic.
	msg := responseTo(header{command: cmdEcho}, statusSuccess)
	signMessage(sigHMAC, nil, msg)
	if binary.LittleEndian.Uint32(msg[offFlags:])&flagSigned != 0 {
		t.Error("a message was marked signed with no key")
	}
	if verifyMessage(sigHMAC, nil, msg) || verifyMessage(sigHMAC, key, msg[:10]) {
		t.Error("something without a key or a header verified")
	}
}

// A man in the middle stripped 3.1.1 from the NEGOTIATE, so the server answered
// 3.0.2; the client's signed validation still lists 3.1.1, and the connection
// must end rather than confirm the downgrade. (Ported from the independent
// review's repro.) The second half checks the greatest-common-dialect rule on
// its own, with a remembered list that matches what the client sends.
func TestValidateNegotiateDowngrade(t *testing.T) {
	validate := func(c *conn, dialects ...uint16) ([]byte, error) {
		in := make([]byte, 24+2*len(dialects))
		binary.LittleEndian.PutUint32(in[0:], 0x7f)
		binary.LittleEndian.PutUint16(in[20:], signingEnabled)
		binary.LittleEndian.PutUint16(in[22:], uint16(len(dialects)))
		for i, d := range dialects {
			binary.LittleEndian.PutUint16(in[24+2*i:], d)
		}
		body := make([]byte, 56)
		binary.LittleEndian.PutUint32(body[4:], fsctlValidateNegotiateInfo)
		binary.LittleEndian.PutUint32(body[24:], uint32(headerLen+56))
		binary.LittleEndian.PutUint32(body[28:], uint32(len(in)))
		binary.LittleEndian.PutUint32(body[44:], 24)
		return c.dispatch(request(cmdIoctl, 0, append(body, in...)))
	}
	c := &conn{srv: New(), dialect: dialect302, clientSecurityMode: signingEnabled, clientCapabilities: 0x7f,
		clientDialects: []uint16{dialect302}}
	if out, err := validate(c, dialect311, dialect302); err == nil {
		t.Errorf("DOWNGRADE: a validation listing 3.1.1 succeeded (%#x) on a 3.0.2 connection", statusOf(t, out))
	}
	c.clientDialects = []uint16{dialect311, dialect302} // what the client really sent, and the server ignored
	if out, err := validate(c, dialect311, dialect302); err == nil {
		t.Errorf("the dialect the server would pick (3.1.1) is not the one it chose, and the answer was %#x", statusOf(t, out))
	}
	// And the honest case passes.
	c.dialect, c.clientDialects = dialect302, []uint16{dialect302}
	if out, err := validate(c, dialect302); err != nil || statusOf(t, out) != statusSuccess {
		t.Errorf("an honest validation: %v", err)
	}
}

// The validation exchange exists because the dialect negotiation happens
// before there is a session to sign it: the client asks the server to repeat
// itself, signed, and compares.
func TestValidateNegotiateInfo(t *testing.T) {
	guid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	c := &conn{srv: New(), dialect: dialect302, clientSecurityMode: signingEnabled, clientCapabilities: 0x7f,
		clientDialects: []uint16{dialect210, dialect302}, clientGuid: guid}

	// askWith sends a VALIDATE_NEGOTIATE_INFO and returns what the dispatcher
	// said: a reply, or the error that ends the connection.
	askWith := func(caps uint32, guid [16]byte, mode uint16, maxOut uint32, dialects ...uint16) ([]byte, error) {
		in := make([]byte, 24+2*len(dialects))
		binary.LittleEndian.PutUint32(in[0:], caps)
		copy(in[4:], guid[:])
		binary.LittleEndian.PutUint16(in[20:], mode)
		binary.LittleEndian.PutUint16(in[22:], uint16(len(dialects)))
		for i, d := range dialects {
			binary.LittleEndian.PutUint16(in[24+2*i:], d)
		}
		body := make([]byte, 56)
		binary.LittleEndian.PutUint32(body[4:], fsctlValidateNegotiateInfo)
		binary.LittleEndian.PutUint32(body[24:], uint32(headerLen+56))
		binary.LittleEndian.PutUint32(body[28:], uint32(len(in)))
		binary.LittleEndian.PutUint32(body[44:], maxOut)
		return c.dispatch(request(cmdIoctl, 0, append(body, in...)))
	}
	ask := func(caps uint32, mode uint16) []byte {
		out, err := askWith(caps, guid, mode, 24, dialect210, dialect302)
		if err != nil {
			t.Fatalf("the control code: %v", err)
		}
		return out
	}

	out := ask(0x7f, signingEnabled)
	if st := statusOf(t, out); st != statusSuccess {
		t.Fatalf("a matching validation answered %#x", st)
	}
	// The client reads the payload through the OUTPUT offset and count, and a
	// response that fills the input ones instead looks empty to it.
	if got := binary.LittleEndian.Uint32(out[headerLen+36:]); got != 24 {
		t.Errorf("the response says its output is %d bytes, want 24", got)
	}
	if got := binary.LittleEndian.Uint32(out[headerLen+32:]); got != headerLen+48 {
		t.Errorf("the response says its output starts at %d", got)
	}
	// What comes back must be what was negotiated, or the client concludes it
	// was tampered with.
	res := out[headerLen+48:]
	if got := binary.LittleEndian.Uint16(res[22:]); got != dialect302 {
		t.Errorf("the validation says the dialect is %#04x", got)
	}
	if !bytes.Equal(res[4:20], c.srv.guid[:]) {
		t.Error("the validation reports a different server identity than the negotiate did")
	}

	// A client whose memory of the exchange differs ends the connection
	// (3.3.5.15.12): every field it repeats is compared, not only two of them.
	other := guid
	other[0]++
	for name, args := range map[string]struct {
		caps     uint32
		guid     [16]byte
		mode     uint16
		maxOut   uint32
		dialects []uint16
	}{
		"capabilities":                     {0x01, guid, signingEnabled, 24, []uint16{dialect210, dialect302}},
		"security mode":                    {0x7f, guid, signingRequired, 24, []uint16{dialect210, dialect302}},
		"the client's GUID":                {0x7f, other, signingEnabled, 24, []uint16{dialect210, dialect302}},
		"a room too small":                 {0x7f, guid, signingEnabled, 23, []uint16{dialect210, dialect302}},
		"fewer dialects":                   {0x7f, guid, signingEnabled, 24, []uint16{dialect302}},
		"a dialect list stripped of 3.1.1": {0x7f, guid, signingEnabled, 24, []uint16{dialect210}},
	} {
		if out, err := askWith(args.caps, args.guid, args.mode, args.maxOut, args.dialects...); err == nil {
			t.Errorf("%s: answered %#x instead of ending the connection", name, statusOf(t, out))
		}
	}

	// Everything else is refused by name.
	body := make([]byte, 56)
	binary.LittleEndian.PutUint32(body[4:], fsctlDfsGetReferrals)
	if st := statusOf(t, mustDispatch(t, c, cmdIoctl, body)); st != statusNotSupported {
		t.Error("a referral request was not refused by name")
	}
	binary.LittleEndian.PutUint32(body[4:], 0x00090000)
	if st := statusOf(t, mustDispatch(t, c, cmdIoctl, body)); st != statusNotSupported {
		t.Error("an unknown control code was not refused by name")
	}
	// A payload that is not inside the message is refused rather than read.
	binary.LittleEndian.PutUint32(body[4:], fsctlValidateNegotiateInfo)
	binary.LittleEndian.PutUint32(body[24:], 1<<20)
	binary.LittleEndian.PutUint32(body[28:], 24)
	if st := statusOf(t, mustDispatch(t, c, cmdIoctl, body)); st != statusInvalidParameter {
		t.Error("a payload outside the message was read anyway")
	}
	if _, err := c.dispatch(request(cmdIoctl, 0, make([]byte, 4))); err == nil {
		t.Error("a body too short to read was accepted")
	}
}
