package smb

import (
	"encoding/binary"
	"testing"
)

// FuzzTransform feeds TRANSFORM_HEADER frames to a connection that has one
// encrypted session. Two inputs reach two depths:
//
//   - frame is sent as it is: it reaches the header checks and, unless the fuzzer
//     forges a tag (it cannot, the keys are not in the input), stops at the tag;
//   - plain is SEALED with the client's keys, so its tag is valid and whatever it
//     contains -- a garbled header, a chain whose NextCommand lies, a request for
//     another session, a related first operation -- is parsed and dispatched.
//
// Whatever a peer sends, the answer is a reply or an error that ends the
// connection: never a panic, and never a plaintext that is not an SMB2 message.
//
// Corpus: testdata/fuzz/FuzzTransform (committed).
func FuzzTransform(f *testing.F) {
	for i, tc := range allCiphers {
		p := newEncPair(f, tc.dialect, tc.cipher)
		echo := append(requestOf(cmdEcho, []byte{4, 0, 0, 0}), 0, 0, 0, 0)
		binary.LittleEndian.PutUint64(echo[offSessionID:], p.sid)
		f.Add(echoFrame(p, p.sid), echo, uint8(i))
	}
	f.Fuzz(func(t *testing.T, frame, plain []byte, which uint8) {
		tc := allCiphers[int(which)%len(allCiphers)]
		p := newEncPair(t, tc.dialect, tc.cipher)
		if len(frame) >= transformLen && binary.LittleEndian.Uint64(frame[offTrSessionID:]) != p.sid {
			// Name the session that exists half of the time, so the decryption is
			// reached and not only the lookup before it.
			binary.LittleEndian.PutUint64(frame[offTrSessionID:], p.sid)
		}
		got, _, err := p.c.decryptFrame(frame)
		if err == nil && (len(got) < headerLen || [4]byte(got[:4]) != protocolID) {
			t.Fatalf("decryptFrame returned %d bytes that are not an SMB2 message", len(got))
		}
		p.c.dispatchChain(frame) // must not panic

		// A valid tag over arbitrary plaintext: opened, then parsed.
		sealed := p.client.seal(p.sid, plain)
		out, err := p.c.dispatchChain(sealed)
		if err == nil && out != nil {
			// A reply to an encrypted request is encrypted, and the client can open it.
			if [4]byte(out[:4]) != transformProtocolID {
				t.Fatalf("a reply to an encrypted request in the clear: %x", out[:min(len(out), 8)])
			}
			if _, err := p.client.open(out); err != nil {
				t.Fatalf("the client cannot open the reply: %v", err)
			}
		}
	})
}
