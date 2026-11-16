package smb

import (
	"encoding/binary"
	"testing"
)

// FuzzTransform feeds TRANSFORM_HEADER frames to a connection that has one
// encrypted session. Whatever a peer sends, the answer is a reply, or an error
// that ends the connection: never a panic, and never a plaintext that is not an
// SMB2 message.
//
// The keys are fixed, so the fuzzer can reach the code behind the
// authentication tag -- a frame it forges would need the key -- through the seed
// frames, which are valid, and the mutations of them that keep the tag valid
// (none) or break it (all but the protocol id).
//
// Corpus: testdata/fuzz/FuzzTransform (committed).
func FuzzTransform(f *testing.F) {
	for i, tc := range allCiphers {
		p := newEncPair(f, tc.dialect, tc.cipher)
		f.Add(echoFrame(p, p.sid), uint8(i))
	}
	f.Fuzz(func(t *testing.T, frame []byte, which uint8) {
		tc := allCiphers[int(which)%len(allCiphers)]
		p := newEncPair(t, tc.dialect, tc.cipher)
		if len(frame) >= transformLen && binary.LittleEndian.Uint64(frame[offTrSessionID:]) != p.sid {
			// Name the session that exists half of the time, so the decryption is
			// reached and not only the lookup before it.
			binary.LittleEndian.PutUint64(frame[offTrSessionID:], p.sid)
		}
		plain, _, err := p.c.decryptFrame(frame)
		if err == nil && (len(plain) < headerLen || [4]byte(plain[:4]) != protocolID) {
			t.Fatalf("decryptFrame returned %d bytes that are not an SMB2 message", len(plain))
		}
		p.c.dispatchChain(frame) // must not panic
	})
}
