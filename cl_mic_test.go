package smb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The mechListMIC is an NTLMSSP signature ([MS-NLMP] 3.4.4.2, extended session
// security) of the mechanism list, at sequence number 0, one key per direction.
// The vectors were produced by this code; the client-to-server one with key
// exchange is the shape Samba 4.22 accepted in the interop run (it refuses a
// client whose MIC is wrong), the others are the same function with the
// other direction's constant or without RC4.

func TestClientNTLMMICKnownAnswers(t *testing.T) {
	exported := bytes.Repeat([]byte{0x55}, 16)
	list := []byte("mechanisms")
	for _, tc := range []struct {
		keyExch, toServer bool
		want              string
	}{
		{false, true, "0100000013c29516621cd64000000000"},
		{false, false, "01000000a90ba8c2a5c88a4900000000"},
		{true, true, "010000001727f873bc05899c00000000"},
		{true, false, "01000000ef03b575f47297a000000000"},
	} {
		got := hex.EncodeToString(ntlmMIC(exported, tc.keyExch, tc.toServer, list))
		if got != tc.want {
			t.Errorf("keyExch=%v toServer=%v: %s", tc.keyExch, tc.toServer, got)
		}
	}
}

func TestClientNTLMMICFraming(t *testing.T) {
	m := ntlmMIC(make([]byte, 16), true, true, []byte("x"))
	if len(m) != 16 || binary.LittleEndian.Uint32(m) != 1 || binary.LittleEndian.Uint32(m[12:]) != 0 {
		t.Fatalf("%x", m)
	}
	// each input changes the checksum
	base := ntlmMIC(make([]byte, 16), false, true, []byte("x"))
	for name, other := range map[string][]byte{
		"key":       ntlmMIC(append(make([]byte, 15), 1), false, true, []byte("x")),
		"direction": ntlmMIC(make([]byte, 16), false, false, []byte("x")),
		"message":   ntlmMIC(make([]byte, 16), false, true, []byte("y")),
		"rc4":       ntlmMIC(make([]byte, 16), true, true, []byte("x")),
	} {
		if bytes.Equal(base[4:12], other[4:12]) {
			t.Errorf("the %s does not reach the checksum", name)
		}
	}
}

func TestClientServerMICIsTheOtherDirection(t *testing.T) {
	n := &clNTLM{exported: bytes.Repeat([]byte{7}, 16), keyExch: true}
	list := clMechTypes()
	fromServer := ntlmMIC(n.exported, true, false, list)
	if !n.serverMICOK(fromServer, list) {
		t.Fatal("the server's own MIC was refused")
	}
	if n.serverMICOK(n.mechListMIC(list), list) {
		t.Error("the client's MIC was taken for the server's")
	}
	if n.serverMICOK(fromServer, append(list, 0)) {
		t.Error("a MIC over another list")
	}
	bad := bytes.Clone(fromServer)
	bad[5] ^= 1
	if n.serverMICOK(bad, list) {
		t.Error("a tampered MIC")
	}
	if n.serverMICOK(fromServer[:15], list) {
		t.Error("a short MIC")
	}
	n.keyExch = false
	if n.serverMICOK(fromServer, list) {
		t.Error("a MIC made with RC4 where none was negotiated")
	}
}

func TestClientNegTokenRespMIC(t *testing.T) {
	mic := bytes.Repeat([]byte{9}, 16)
	got, err := negTokenRespMIC(spnegoRespToken([]byte("NTLMSSP"), mic))
	if err != nil || !bytes.Equal(got, mic) {
		t.Fatalf("%x %v", got, err)
	}
	// a token without one has none
	bare := derCtx(1, derSeq(append(derCtx(0, derEnum(1)), derCtx(2, derOctet([]byte("t")))...)))
	if got, err := negTokenRespMIC(bare); err != nil || got != nil {
		t.Fatalf("%x %v", got, err)
	}
	for name, b := range map[string][]byte{
		"empty":         nil,
		"not a resp":    derCtx(0, derSeq(nil)),
		"not a seq":     derCtx(1, derOctet(nil)),
		"cut field":     derCtx(1, derSeq([]byte{0xA3, 0x20, 0x04})),
		"mic not octet": derCtx(1, derSeq(derCtx(3, derSeq(nil)))),
	} {
		if got, err := negTokenRespMIC(b); err == nil {
			t.Errorf("%s: accepted: %x", name, got)
		}
	}
	// the token still carries the NTLM message the usual way
	tok, _, err := mechTokenOf(spnegoRespToken([]byte("NTLMSSP\x00x"), mic))
	if err != nil || string(tok) != "NTLMSSP\x00x" {
		t.Fatalf("%q %v", tok, err)
	}
}

// finalResponse is a SESSION_SETUP response signed with the key a client that
// derived exported and pre would use.
func finalResponse(t *testing.T, key []byte, status uint32, flags uint16, sec []byte) clResult {
	t.Helper()
	m := respMsg(cmdSessionSetup, 1, status, flagServerToRedir, 0, 1)[:headerLen]
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b, 9)
	binary.LittleEndian.PutUint16(b[2:], flags)
	binary.LittleEndian.PutUint16(b[4:], headerLen+8)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(sec)))
	m = append(append(m, b...), sec...)
	signMessage(sigCMAC, key, m)
	h, err := parseHeader(m)
	if err != nil {
		t.Fatal(err)
	}
	return clResult{msg: m, h: h}
}

func TestClientFinishSession(t *testing.T) {
	defer recovered(t)
	exported := bytes.Repeat([]byte{3}, 16)
	pre := bytes.Repeat([]byte{4}, 64)
	key := signingKeyFor(dialect311, exported, pre)
	nt := &clNTLM{exported: exported, keyExch: true}
	list := clMechTypes()
	goodTok := derCtx(1, derSeq(derCtx(3, derOctet(ntlmMIC(exported, true, false, list)))))
	wrongTok := derCtx(1, derSeq(derCtx(3, derOctet(ntlmMIC(exported, true, true, list)))))
	conn := func(allowPlain bool) *ClientConn {
		return &ClientConn{sigAlg: sigCMAC, cipherID: cipherAES128GCM, o: ClientOptions{AllowUnencrypted: allowPlain}}
	}

	for name, tc := range map[string]struct {
		r    clResult
		want string
	}{
		"a status":          {finalResponse(t, key, 0xC000006D, 0, nil), "SESSION_SETUP"},
		"too short":         {clResult{msg: respMsg(cmdSessionSetup, 1, 0, flagServerToRedir, 0, 1)[:headerLen+3], h: header{}}, "shorter than its structure"},
		"a guest":           {finalResponse(t, key, 0, 1, nil), "guest or anonymous"},
		"an anonymous":      {finalResponse(t, key, 0, 2, nil), "guest or anonymous"},
		"another key":       {finalResponse(t, make([]byte, 16), 0, 0, nil), "not correctly signed"},
		"a wrong MIC":       {finalResponse(t, key, 0, 0, wrongTok), "mechListMIC is wrong"},
		"a broken token":    {finalResponse(t, key, 0, 0, []byte{0xA1, 0x30}), "SPNEGO"},
		"a bad buffer":      {badBuffer(t, key), "outside"},
		"neither the other": {finalResponse(t, key, 0, 0, derCtx(0, derSeq(nil))), "SPNEGO"},
	} {
		c := conn(false)
		err := c.finishSession(tc.r, nt, pre)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
		if c.ready {
			t.Errorf("%s: the connection went ready", name)
		}
	}
	var se *StatusError
	if err := conn(false).finishSession(finalResponse(t, key, 0xC000006D, 0, nil), nt, pre); !errors.As(err, &se) || se.Status != 0xC000006D {
		t.Errorf("a status error: %v", err)
	}

	// the good ones: with the server's MIC, with none, and with an empty token
	for name, sec := range map[string][]byte{"with a MIC": goodTok, "without one": nil, "a token without a MIC": derCtx(1, derSeq(derCtx(0, derEnum(0))))} {
		c := conn(false)
		if err := c.finishSession(finalResponse(t, key, 0, 0, sec), nt, pre); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !c.ready || !c.encrypted || c.enc == nil || c.dec == nil || !bytes.Equal(c.signKey, key) {
			t.Errorf("%s: ready=%v encrypted=%v", name, c.ready, c.encrypted)
		}
	}
	// the two directions get two keys
	c := conn(false)
	if err := c.finishSession(finalResponse(t, key, 0, 0, nil), nt, pre); err != nil {
		t.Fatal(err)
	}
	probe := make([]byte, c.enc.NonceSize())
	if bytes.Equal(c.enc.Seal(nil, probe, []byte("x"), nil), c.dec.Seal(nil, probe, []byte("x"), nil)) {
		t.Error("one key for both directions")
	}
	// plain traffic is allowed only where asked for and where the server did not demand encryption
	c = conn(true)
	if err := c.finishSession(finalResponse(t, key, 0, 0, nil), nt, pre); err != nil || c.encrypted {
		t.Errorf("AllowUnencrypted: %v encrypted=%v", err, c.encrypted)
	}
	c = conn(true)
	if err := c.finishSession(finalResponse(t, key, 0, sessionFlagEncryptData, nil), nt, pre); err != nil || !c.encrypted {
		t.Errorf("a session the server encrypts: %v encrypted=%v", err, c.encrypted)
	}
	// no cipher negotiated: no keys, never encrypted
	c = conn(false)
	c.cipherID = cipherNone
	if err := c.finishSession(finalResponse(t, key, 0, 0, nil), nt, pre); err != nil || c.encrypted || c.enc != nil || c.dec != nil || !c.ready {
		t.Errorf("no cipher: %v", err)
	}
}

func badBuffer(t *testing.T, key []byte) clResult {
	r := finalResponse(t, key, 0, 0, []byte{1, 2, 3, 4})
	binary.LittleEndian.PutUint16(r.msg[headerLen+6:], 5000)
	signMessage(sigCMAC, key, r.msg)
	return r
}
