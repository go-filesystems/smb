package smb

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"testing"
)

// SMB2_TRANSPORT_CAPABILITIES ([MS-SMB2] 2.2.3.1.5) and what a QUIC connection
// changes in NEGOTIATE ([MS-SMB2] 3.3.5.4).

func transCtx(flags uint32) outContext {
	d := make([]byte, 4)
	binary.LittleEndian.PutUint32(d, flags)
	return outContext{ctxTransportCaps, d}
}

// answeredContexts returns the types of the contexts in a NEGOTIATE answer and
// the data of the transport one.
func answeredContexts(t *testing.T, resp []byte) (types []uint16, transport []byte) {
	t.Helper()
	body := resp[headerLen:]
	n := int(binary.LittleEndian.Uint16(body[6:]))
	off := int(binary.LittleEndian.Uint32(body[60:]))
	for i := 0; i < n; i++ {
		typ := binary.LittleEndian.Uint16(resp[off:])
		dl := int(binary.LittleEndian.Uint16(resp[off+2:]))
		if typ == ctxTransportCaps {
			transport = resp[off+8 : off+8+dl]
		}
		types = append(types, typ)
		off = (off + 8 + dl + 7) &^ 7
	}
	return types, transport
}

func negotiateOn(t *testing.T, transport string, srv *Server, ctxs ...outContext) (*conn, []byte) {
	t.Helper()
	req := negotiateRequest311(append([]outContext{
		ctxPreauth([]uint16{hashIDSHA512}, make([]byte, 32)),
		ctxList(ctxEncryption, 2, 1),
	}, ctxs...)...)
	c := &conn{srv: srv, transport: transport}
	resp, err := c.dispatch(req)
	if err != nil {
		t.Fatal(err)
	}
	return c, resp
}

func TestTransportCapabilitiesOverQUIC(t *testing.T) {
	t.Run("short context fails the request", func(t *testing.T) {
		_, resp := negotiateOn(t, "quic", New(), outContext{ctxTransportCaps, []byte{1, 0, 0}})
		if st := statusOf(t, resp); st != statusInvalidParameter {
			t.Fatalf("status %#x, want STATUS_INVALID_PARAMETER", st)
		}
	})
	t.Run("empty context fails the request", func(t *testing.T) {
		_, resp := negotiateOn(t, "quic", New(), outContext{ctxTransportCaps, nil})
		if st := statusOf(t, resp); st != statusInvalidParameter {
			t.Fatalf("status %#x", st)
		}
	})
	t.Run("two contexts fail the request", func(t *testing.T) {
		_, resp := negotiateOn(t, "quic", New(), transCtx(1), transCtx(1))
		if st := statusOf(t, resp); st != statusInvalidParameter {
			t.Fatalf("status %#x", st)
		}
	})
	t.Run("default: flag offered, not accepted, encryption stays", func(t *testing.T) {
		c, resp := negotiateOn(t, "quic", New(), transCtx(flagAcceptTransportSecurity))
		types, tr := answeredContexts(t, resp)
		if tr != nil || c.acceptTransportSecurity {
			t.Fatalf("transport security accepted by default: %v", types)
		}
		if !bytes.Contains(typesBytes(types), typesBytes([]uint16{ctxEncryption})) {
			t.Fatalf("no encryption context in %v", types)
		}
	})
	t.Run("option on: flag answered, encryption not negotiated", func(t *testing.T) {
		srv := New()
		srv.DisableEncryptionOverSecureTransport = true
		c, resp := negotiateOn(t, "quic", srv, transCtx(flagAcceptTransportSecurity))
		types, tr := answeredContexts(t, resp)
		if len(tr) != 4 || binary.LittleEndian.Uint32(tr) != flagAcceptTransportSecurity || !c.acceptTransportSecurity {
			t.Fatalf("answer %x accept=%v", tr, c.acceptTransportSecurity)
		}
		for _, ty := range types {
			if ty == ctxEncryption {
				t.Fatalf("an encryption context was answered: %v", types)
			}
		}
	})
	t.Run("option on, flag not set by the client", func(t *testing.T) {
		srv := New()
		srv.DisableEncryptionOverSecureTransport = true
		c, resp := negotiateOn(t, "quic", srv, transCtx(0))
		if _, tr := answeredContexts(t, resp); tr != nil || c.acceptTransportSecurity {
			t.Fatal("accepted a flag the client did not set")
		}
	})
	t.Run("over TCP the context is ignored", func(t *testing.T) {
		srv := New()
		srv.DisableEncryptionOverSecureTransport = true
		for _, ctx := range []outContext{transCtx(1), {ctxTransportCaps, []byte{1}}} {
			c, resp := negotiateOn(t, "tcp", srv, ctx)
			if st := statusOf(t, resp); st != statusSuccess {
				t.Fatalf("status %#x over TCP", st)
			}
			if _, tr := answeredContexts(t, resp); tr != nil || c.acceptTransportSecurity {
				t.Fatal("TCP accepted transport security")
			}
		}
	})
}

func typesBytes(ts []uint16) []byte {
	var b []byte
	for _, x := range ts {
		b = binary.LittleEndian.AppendUint16(b, x)
	}
	return b
}

// [MS-SMB2] 3.3.5.4: multi-credit only on TCP 445 or RDMA.
func TestMultiCreditOnlyOffTheWireOfQUIC(t *testing.T) {
	for _, tc := range []struct {
		transport string
		wantMTU   bool
		wantRead  uint32
	}{{"tcp", true, maxReadSize}, {"quic", false, 65536}} {
		_, resp := negotiateOn(t, tc.transport, New())
		body := resp[headerLen:]
		caps := binary.LittleEndian.Uint32(body[24:])
		if got := caps&capLargeMTU != 0; got != tc.wantMTU {
			t.Errorf("%s: LARGE_MTU = %v, want %v", tc.transport, got, tc.wantMTU)
		}
		for _, off := range []int{28, 32, 36} {
			if got := binary.LittleEndian.Uint32(body[off:]); got != tc.wantRead {
				t.Errorf("%s: size at %d = %d, want %d", tc.transport, off, got, tc.wantRead)
			}
		}
	}
}

// FuzzTransportCaps feeds NEGOTIATE requests whose contexts include
// SMB2_TRANSPORT_CAPABILITIES to a QUIC connection, with and without the option
// that accepts transport security: never a panic, and the flag is accepted only
// when the client set it and the option is on.
//
// Corpus: testdata/fuzz/FuzzTransportCaps (committed).
func FuzzTransportCaps(f *testing.F) {
	pre := ctxPreauth([]uint16{hashIDSHA512}, make([]byte, 32))
	f.Add(negotiateRequest311(pre, transCtx(1)), true)
	f.Add(negotiateRequest311(pre, transCtx(0)), true)
	f.Add(negotiateRequest311(pre, outContext{ctxTransportCaps, []byte{1, 0}}), true)
	f.Add(negotiateRequest311(pre, transCtx(1), transCtx(1)), false)
	f.Fuzz(func(t *testing.T, msg []byte, opt bool) {
		srv := New()
		srv.DisableEncryptionOverSecureTransport = opt
		c := &conn{srv: srv, transport: "quic"}
		if _, err := c.dispatch(msg); err != nil {
			return
		}
		if c.acceptTransportSecurity && !opt {
			t.Fatal("accepted transport security with the option off")
		}
	})
}

// FuzzParseClientCAs reads a CA bundle from arbitrary bytes: an error or a pool,
// never a panic, and a pool only with at least one certificate.
//
// Corpus: testdata/fuzz/FuzzParseClientCAs (committed).
func FuzzParseClientCAs(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	f.Add(bytes.Repeat([]byte("-----BEGIN CERTIFICATE-----\n"), 100))
	f.Fuzz(func(t *testing.T, b []byte) {
		pool, err := ParseClientCAs(b)
		if (pool == nil) == (err == nil) {
			t.Fatalf("pool=%v err=%v", pool, err)
		}
		conf := &tls.Config{}
		if err := RequireClientCertificate(conf, b); err != nil && conf.ClientAuth != tls.NoClientCert {
			t.Fatal("RequireClientCertificate set ClientAuth and failed")
		}
	})
}

func TestParseClientCAsRefuses(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":       nil,
		"text":        []byte("not pem"),
		"key":         []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
		"garbage der": []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		"huge":        make([]byte, maxClientCAFileBytes+1),
	} {
		if _, err := ParseClientCAs(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	conf := &tls.Config{}
	if err := RequireClientCertificate(conf, nil); err == nil || conf.ClientAuth != tls.NoClientCert {
		t.Fatal("an empty CA file turned client certificates on")
	}
}
