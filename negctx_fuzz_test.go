package smb

import "testing"

// FuzzNegotiate feeds NEGOTIATE requests, negotiate contexts included, to a
// fresh connection: whatever a peer sends before it has authenticated, the
// answer is a reply or an error, never a panic, and a context list is never
// read outside the message.
//
// Corpus: testdata/fuzz/FuzzNegotiate (committed).
func FuzzNegotiate(f *testing.F) {
	f.Add(negotiateRequest(dialect302))
	f.Add(negotiateRequest311(ctxPreauth([]uint16{hashIDSHA512}, make([]byte, 32))))
	f.Add(negotiateRequest311(
		ctxPreauth([]uint16{hashIDSHA512}, nil),
		ctxList(ctxEncryption, 2, 1),
		ctxList(ctxSigning, signIDAESGMAC, signIDAESCMAC),
		outContext{0x0005, []byte("host\x00")},
	))
	f.Fuzz(func(t *testing.T, msg []byte) {
		c := &conn{srv: New()}
		out, err := c.dispatch(msg)
		if err != nil {
			return
		}
		// An answer is a header and a body (CANCEL has none: nil), and a 3.1.1
		// success leaves the hash chain started.
		if out != nil && len(out) < headerLen {
			t.Fatalf("an answer of %d bytes", len(out))
		}
		if c.dialect == dialect311 && len(c.preauth) != preauthHashSize {
			t.Fatalf("3.1.1 chosen with a preauth hash of %d bytes", len(c.preauth))
		}
	})
}
