package smb

import (
	"encoding/binary"
	"testing"
)

// [MS-SMB2] 3.3.5.4: SecurityMode of the NEGOTIATE response has signing enabled,
// and required when the server requires it; the validation repeats it.
func TestTheNegotiateResponseSaysWhetherTheServerRequiresSigning(t *testing.T) {
	for _, required := range []bool{false, true} {
		srv := New()
		srv.RequireSigning = required
		c := &conn{srv: srv}
		resp, err := c.dispatch(negotiateRequest(dialect302))
		if err != nil {
			t.Fatal(err)
		}
		mode := binary.LittleEndian.Uint16(resp[headerLen+2:])
		want := signingEnabled
		if required {
			want |= signingRequired
		}
		if mode != want {
			t.Errorf("RequireSigning=%v: SecurityMode %#x, want %#x", required, mode, want)
		}
		if got := c.serverSecurityMode(); got != want {
			t.Errorf("serverSecurityMode %#x", got)
		}
		// VALIDATE_NEGOTIATE_INFO says the same, or an honest client concludes it was
		// tampered with.
		in := make([]byte, 24+4)
		binary.LittleEndian.PutUint32(in[0:], c.clientCapabilities)
		copy(in[4:], c.clientGuid[:])
		binary.LittleEndian.PutUint16(in[20:], c.clientSecurityMode)
		binary.LittleEndian.PutUint16(in[22:], uint16(len(c.clientDialects)))
		for i, d := range c.clientDialects {
			binary.LittleEndian.PutUint16(in[24+2*i:], d)
		}
		body := make([]byte, 56)
		binary.LittleEndian.PutUint32(body[4:], fsctlValidateNegotiateInfo)
		binary.LittleEndian.PutUint32(body[24:], uint32(headerLen+56))
		binary.LittleEndian.PutUint32(body[28:], uint32(len(in)))
		binary.LittleEndian.PutUint32(body[44:], 24)
		out, err := c.dispatch(request(cmdIoctl, 0, append(body, in...)))
		if err != nil {
			t.Fatal(err)
		}
		if got := binary.LittleEndian.Uint16(out[headerLen+48+20:]); got != want {
			t.Errorf("RequireSigning=%v: the validation says SecurityMode %#x, want %#x", required, got, want)
		}
	}
}
