package smb

import (
	"encoding/binary"
	"testing"
)

// Each reply of a compounded chain is signed over the whole message INCLUDING the
// padding that brings it to an eight-byte boundary and the NextCommand that says
// where the next one starts ([MS-SMB2] 3.1.4.1: "any padding at the end of the
// message MUST be used in the hash computation"). The server signed first and
// padded after, so a client that verifies compounded replies -- macOS, once the
// server required signing -- rejected them and dropped the mount.
func TestTheRepliesOfASignedCompoundVerify(t *testing.T) {
	for _, dialect := range []uint16{dialect210, dialect302, dialect311} {
		r := requiringConn(t, dialect)
		c := r.c
		// Three operations, signed one by one, each padded to 8 bytes.
		var chain []byte
		for i := 0; i < 3; i++ {
			m := r.unsigned(cmdEcho, []byte{4, 0, 0, 0})
			for len(m)%8 != 0 {
				m = append(m, 0)
			}
			if i < 2 {
				binary.LittleEndian.PutUint32(m[offNextCommand:], uint32(len(m)))
			}
			signMessage(c.signAlgo(), r.key, m)
			chain = append(chain, m...)
		}
		out, err := c.dispatchChain(chain)
		if err != nil {
			t.Fatalf("%s: %v", dialectName(dialect), err)
		}
		n := 0
		for rest := out; len(rest) >= headerLen; n++ {
			h, err := parseHeader(rest)
			if err != nil {
				t.Fatal(err)
			}
			msg := rest
			if h.nextCommand != 0 {
				if h.nextCommand%8 != 0 || int(h.nextCommand) > len(rest) {
					t.Fatalf("%s: reply %d says the next starts at %d of %d", dialectName(dialect), n, h.nextCommand, len(rest))
				}
				msg = rest[:h.nextCommand]
			}
			if h.status != statusSuccess {
				t.Errorf("%s: reply %d answered %#x", dialectName(dialect), n, h.status)
			}
			if !verifyMessage(c.signAlgo(), r.key, msg) {
				t.Errorf("%s: reply %d of the compound does not verify as the client reads it (padding and NextCommand included)", dialectName(dialect), n)
			}
			if h.nextCommand == 0 {
				break
			}
			rest = rest[h.nextCommand:]
		}
		if n != 2 {
			t.Errorf("%s: %d replies were walked, want 3", dialectName(dialect), n+1)
		}
	}
}
