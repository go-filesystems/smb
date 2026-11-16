package smb

import (
	"encoding/binary"
	"testing"
)

// sessionSetupRequest wraps an authentication token in a SESSION_SETUP request.
func sessionSetupRequest(session uint64, token []byte) []byte {
	body := make([]byte, 24+len(token))
	putU16(body[0:], 25)
	putU16(body[12:], headerLen+24)
	putU16(body[14:], uint16(len(token)))
	copy(body[24:], token)
	m := requestOf(cmdSessionSetup, body)
	binary.LittleEndian.PutUint64(m[offSessionID:], session)
	return m
}

func ntlmNegotiateToken() []byte {
	t := make([]byte, 32)
	copy(t, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(t[8:], 1)
	return t
}

// FuzzSessionSetup drives the authentication leg of a 3.1.1 connection: the
// connection has negotiated, a first SESSION_SETUP has been answered with a
// challenge, and the fuzzed message arrives as whatever comes next -- a second
// SESSION_SETUP, a request that names the session, a transform header. Whatever
// it is, the answer is a reply or an error, never a panic, and a session that
// the exchange did not create is never installed.
//
// Corpus: testdata/fuzz/FuzzSessionSetup (committed).
func FuzzSessionSetup(f *testing.F) {
	f.Add(sessionSetupRequest(1, ntlmNegotiateToken()))
	f.Add(sessionSetupRequest(0, ntlmNegotiateToken()))
	f.Add(sessionSetupRequest(1, append(append([]byte(nil), "NTLMSSP\x00"...), 3, 0, 0, 0)))
	f.Add(sessionSetupRequest(1, []byte{0x60, 0x03, 0x06, 0x01, 0x05}))
	f.Add(sessionSetupRequest(1, nil))
	f.Fuzz(func(t *testing.T, msg []byte) {
		c := &conn{srv: New()}
		c.sessions, c.trees, c.files, c.searches, c.waiting = map[uint64]*session{}, map[uint32]*treeConn{}, map[[16]byte]*openFile{}, map[[16]byte]*search{}, map[uint64]*pendingOp{}
		if _, err := c.dispatchChain(negotiateRequest311(ctxPreauth([]uint16{hashIDSHA512}, nil))); err != nil {
			t.Fatal(err)
		}
		if out, err := c.dispatchChain(sessionSetupRequest(0, ntlmNegotiateToken())); err != nil || statusOf(t, out) != statusMoreProcessing {
			t.Fatalf("the first leg: %v", err)
		}
		c.dispatchChain(msg) // must not panic
		for id := range c.sessions {
			// Nothing authenticated: with no credentials supplied to the server, no
			// session can exist.
			t.Fatalf("a session %d exists although nobody authenticated", id)
		}
	})
}
