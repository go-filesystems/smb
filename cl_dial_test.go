package smb_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	fssmb "github.com/go-filesystems/smb"
)

// rewriteProxy relays one connection to upstream and passes every
// server-to-client message (without its length header) through edit, which is
// given the index of the message. edit returns the message to send, or nil to
// close the connection instead.
func rewriteProxy(t *testing.T, upstream string, edit func(i int, m []byte) []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		cc, err := ln.Accept()
		if err != nil {
			return
		}
		sc, err := net.Dial("tcp", upstream)
		if err != nil {
			cc.Close()
			return
		}
		go io.Copy(sc, cc)
		for i := 0; ; i++ {
			var hdr [4]byte
			if _, err := io.ReadFull(sc, hdr[:]); err != nil {
				cc.Close()
				return
			}
			body := make([]byte, int(hdr[1])<<16|int(hdr[2])<<8|int(hdr[3]))
			if _, err := io.ReadFull(sc, body); err != nil {
				cc.Close()
				return
			}
			out := edit(i, body)
			if out == nil {
				cc.Close()
				sc.Close()
				return
			}
			frame := binary.BigEndian.AppendUint32(nil, uint32(len(out)))
			cc.Write(append(frame, out...))
		}
	}()
	return ln.Addr().String()
}

func put16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func put32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

// ctxAt returns the offset, in a NEGOTIATE response, of the context of type typ.
func ctxAt(t *testing.T, m []byte, typ uint16) int {
	t.Helper()
	off := int(binary.LittleEndian.Uint32(m[64+60:]))
	for i := 0; i < int(binary.LittleEndian.Uint16(m[64+6:])); i++ {
		dlen := int(binary.LittleEndian.Uint16(m[off+2:]))
		if binary.LittleEndian.Uint16(m[off:]) == typ {
			return off
		}
		off = (off + 8 + dlen + 7) &^ 7
	}
	t.Fatalf("no context of type %d", typ)
	return 0
}

func dialThrough(t *testing.T, plain bool, edit func(i int, m []byte) []byte) error {
	t.Helper()
	addr, _ := serve(t)
	_, err := clDial(t, rewriteProxy(t, addr, edit), "alice", "hunter2", plain)
	return err
}

// only edits message n, and leaves the others alone.
func only(n int, f func(m []byte) []byte) func(i int, m []byte) []byte {
	return func(i int, m []byte) []byte {
		if i == n {
			return f(m)
		}
		return m
	}
}

func wantErr(t *testing.T, name string, err error, sub string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), sub) {
		t.Errorf("%s: %v, want %q", name, err, sub)
	}
}

func TestTheOwnClientEngineRefusesWhatTheNegotiateGotWrong(t *testing.T) {
	const ctxEnc, ctxSign, ctxPre = 2, 8, 1
	for _, tc := range []struct {
		name string
		edit func(m []byte) []byte
		want string
	}{
		{"status", func(m []byte) []byte { put32(m, 8, 0xC0000022); return m }, "NEGOTIATE"},
		{"truncated", func(m []byte) []byte { return m[:64+10] }, "shorter than its structure"},
		{"another dialect", func(m []byte) []byte { put16(m, 64+4, 0x0302); return m }, "which was not offered"},
		{"no contexts", func(m []byte) []byte { put16(m, 64+6, 0); return m }, "points outside the message"},
		{"another hash", func(m []byte) []byte { put16(m, ctxAt(t, m, ctxPre)+8+4, 0x0002); return m }, "pre-authentication hash"},
		{"a signing algorithm that was not offered", func(m []byte) []byte { put16(m, ctxAt(t, m, ctxSign)+8+2, 99); return m }, "signing algorithm 99"},
		{"a cipher that was not offered", func(m []byte) []byte { put16(m, ctxAt(t, m, ctxEnc)+8+2, 99); return m }, "cipher 99"},
		{"no cipher context", func(m []byte) []byte { put16(m, ctxAt(t, m, ctxEnc), 0x00FF); return m }, fssmb.ErrEncryptionRequired.Error()},
		{"cipher none", func(m []byte) []byte { put16(m, ctxAt(t, m, ctxEnc)+8+2, 0); return m }, fssmb.ErrEncryptionRequired.Error()},
		{"a server that does not sign", func(m []byte) []byte { put16(m, 64+2, 0); return m }, "does not sign"},
	} {
		wantErr(t, tc.name, dialThrough(t, false, only(0, tc.edit)), tc.want)
	}
	// signing enabled alone is enough
	err := dialThrough(t, false, only(0, func(m []byte) []byte { put16(m, 64+2, 1); return m }))
	if err != nil && strings.Contains(err.Error(), "does not sign") {
		t.Errorf("a server that signs when asked was refused: %v", err)
	}
	// ... and so is required alone
	err = dialThrough(t, false, only(0, func(m []byte) []byte { put16(m, 64+2, 2); return m }))
	if err != nil && strings.Contains(err.Error(), "does not sign") {
		t.Errorf("a server that requires signing was refused: %v", err)
	}
	// a server that offers no cipher may be talked to only when asked to
	err = dialThrough(t, true, only(0, func(m []byte) []byte { put16(m, ctxAt(t, m, ctxEnc)+8+2, 0); return m }))
	if errors.Is(err, fssmb.ErrEncryptionRequired) {
		t.Errorf("AllowUnencrypted was ignored: %v", err)
	}
}

func ntlmAt(t *testing.T, m []byte) int {
	t.Helper()
	i := bytes.Index(m, []byte("NTLMSSP\x00"))
	if i < 0 {
		t.Fatal("no NTLMSSP in the message")
	}
	return i
}

func TestTheOwnClientEngineRefusesWhatTheSessionSetupGotWrong(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		edit func(m []byte) []byte
		want string
	}{
		{"challenge: status", 1, func(m []byte) []byte { put32(m, 8, 0xC000006D); return m }, "SESSION_SETUP"},
		{"challenge: truncated", 1, func(m []byte) []byte { return m[:64+4] }, "shorter than its structure"},
		{"challenge: no token", 1, func(m []byte) []byte {
			put16(m, 64+6, 0)
			return m
		}, "SPNEGO"},
		{"challenge: not NTLM", 1, func(m []byte) []byte { m[ntlmAt(t, m)] ^= 1; return m }, "not an NTLM message"},
		{"challenge: no unicode", 1, func(m []byte) []byte {
			i := ntlmAt(t, m)
			put32(m, i+20, binary.LittleEndian.Uint32(m[i+20:])&^1)
			return m
		}, "does not offer Unicode"},
		{"challenge: target info that is not a list", 1, func(m []byte) []byte {
			put16(m, ntlmAt(t, m)+40, 1)
			return m
		}, "not an NTLM message"},
		{"final: status", 2, func(m []byte) []byte { put32(m, 8, 0xC0000022); return m }, "SESSION_SETUP"},
		{"final: truncated", 2, func(m []byte) []byte { return m[:64+4] }, "shorter than its structure"},
		{"final: guest", 2, func(m []byte) []byte { put16(m, 64+2, 1); return m }, "guest or anonymous"},
		{"final: null", 2, func(m []byte) []byte { put16(m, 64+2, 2); return m }, "guest or anonymous"},
		{"final: wrong signature", 2, func(m []byte) []byte { m[48] ^= 1; return m }, "not correctly signed"},
		{"final: unsigned", 2, func(m []byte) []byte { put32(m, 16, binary.LittleEndian.Uint32(m[16:])&^8); return m }, "not correctly signed"},
		{"final: body altered", 2, func(m []byte) []byte { m[len(m)-1] ^= 1; return m }, "not correctly signed"},
	} {
		err := dialThrough(t, false, only(tc.n, tc.edit))
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if tc.want != "" {
			wantErr(t, tc.name, err, tc.want)
		}
		var se *fssmb.StatusError
		if strings.HasSuffix(tc.name, "status") != errors.As(err, &se) {
			t.Errorf("%s: a status error is expected exactly for the status cases: %v", tc.name, err)
		}
		if tc.name == "challenge: no token" || tc.name == "challenge: not NTLM" {
			// whatever it is, it is refused before a credential is sent and is not
			// a mere failure of the exchange
			if strings.Contains(err.Error(), "SESSION_SETUP") || strings.Contains(err.Error(), "not correctly signed") {
				t.Errorf("%s: reached the end of the exchange: %v", tc.name, err)
			}
		}
	}
}

// A connection cut at any message of the session ends the dial with the cut
// itself, never with a decoding error from an empty message.
func TestTheOwnClientEngineReportsAConnectionCutAtEachStage(t *testing.T) {
	for n := 0; n < 3; n++ {
		err := dialThrough(t, false, func(i int, m []byte) []byte {
			if i == n {
				return nil
			}
			return m
		})
		if err == nil {
			t.Fatalf("cut at %d: dialled", n)
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, net.ErrClosed) && !errors.As(err, new(net.Error)) {
			t.Errorf("cut at %d: not a transport error: %v", n, err)
		}
		for _, bad := range []string{"shorter than its structure", "points outside", "not an NTLM", "SESSION_SETUP", "NEGOTIATE", "signed"} {
			if strings.Contains(err.Error(), bad) {
				t.Errorf("cut at %d: %v", n, err)
			}
		}
	}
}
