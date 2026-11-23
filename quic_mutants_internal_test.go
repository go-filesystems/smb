package smb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// Tests that assert the value on both sides of each guard mutsweep found
// held by nothing (or only by a panic) in the QUIC change.

// ctxBytes is one context header + data, padded to 8 bytes.
func ctxBytes(typ uint16, data []byte) []byte {
	b := make([]byte, 8, 8+len(data)+7)
	binary.LittleEndian.PutUint16(b, typ)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(data)))
	b = append(b, data...)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	return b
}

func u16s(v ...uint16) []byte {
	b := make([]byte, 2*len(v))
	for i, x := range v {
		binary.LittleEndian.PutUint16(b[2*i:], x)
	}
	return b
}

// preauthData is a well-formed PREAUTH_INTEGRITY_CAPABILITIES body.
func preauthData() []byte { return append(u16s(1, 0), u16s(hashIDSHA512)...) }

// at puts contexts at off in a message whose header is zeroes.
func at(off int, ctxs ...[]byte) []byte {
	m := make([]byte, off)
	for _, c := range ctxs {
		m = append(m, c...)
	}
	return m
}

func TestParseNegotiateContextsGuards(t *testing.T) {
	good := ctxBytes(ctxPreauthIntegrity, preauthData())
	if _, st := parseNegotiateContexts(at(headerLen, good), headerLen, 1); st != 0 {
		t.Fatalf("the well-formed context is refused: %#x", st)
	}
	many := [][]byte{good}
	for i := 0; i < maxNegotiateContexts; i++ {
		many = append(many, ctxBytes(0x00ff, nil))
	}
	bad := []struct {
		name  string
		msg   []byte
		off   int
		count int
	}{
		{"no context", at(headerLen, good), headerLen, 0},
		{"more contexts than the bound", at(headerLen, many...), headerLen, maxNegotiateContexts + 1},
		{"offset inside the header", at(headerLen-8, good), headerLen - 8, 1},
		{"offset not 8-aligned", at(headerLen+1, good), headerLen + 1, 1},
		{"offset past the message", at(headerLen, good), len(good) + headerLen + 8, 1},
		{"a context header cut off", at(headerLen, good[:4]), headerLen, 1},
		{"a context longer than the message", at(headerLen, func() []byte { c := ctxBytes(ctxPreauthIntegrity, preauthData()); return c[:len(c)-8] }()), headerLen, 1},
		{"preauth under 4 bytes", at(headerLen, ctxBytes(ctxPreauthIntegrity, []byte{1, 0, 0})), headerLen, 1},
		{"preauth with no algorithm", at(headerLen, ctxBytes(ctxPreauthIntegrity, u16s(0, 0))), headerLen, 1},
		{"preauth arrays past the data", at(headerLen, ctxBytes(ctxPreauthIntegrity, append(u16s(1, 32), u16s(hashIDSHA512)...))), headerLen, 1},
		{"encryption under 2 bytes", at(headerLen, good, ctxBytes(ctxEncryption, []byte{1})), headerLen, 2},
		{"encryption array past the data", at(headerLen, good, ctxBytes(ctxEncryption, u16s(5, 1))), headerLen, 2},
		{"signing under 2 bytes", at(headerLen, good, ctxBytes(ctxSigning, []byte{1})), headerLen, 2},
		{"signing with no algorithm", at(headerLen, good, ctxBytes(ctxSigning, u16s(0))), headerLen, 2},
		{"signing array past the data", at(headerLen, good, ctxBytes(ctxSigning, u16s(5, 1))), headerLen, 2},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, st := parseNegotiateContexts(c.msg, c.off, c.count); st != statusInvalidParameter {
				t.Fatalf("status %#x, want STATUS_INVALID_PARAMETER", st)
			}
		})
	}
	// The same arrays, exactly as long as their data: accepted.
	for name, ctx := range map[string][]byte{
		"encryption":  ctxBytes(ctxEncryption, u16s(1, 1)),
		"signing":     ctxBytes(ctxSigning, u16s(1, 1)),
		"unknown too": ctxBytes(0x00ff, []byte{1, 2, 3}),
	} {
		if _, st := parseNegotiateContexts(at(headerLen, good, ctx), headerLen, 2); st != 0 {
			t.Fatalf("%s: a context exactly as long as its array is refused: %#x", name, st)
		}
	}
}

func TestPayloadSizeShortBodyBothSides(t *testing.T) {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[4:], 5000)
	if got := payloadSize(cmdRead, body); got != 5000 {
		t.Fatalf("a body just long enough for Length: %d, want 5000", got)
	}
	// Short of Length, the field reads as 0 and the size is the body's own 7.
	if got := payloadSize(cmdRead, body[:7]); got != 7 {
		t.Fatalf("a body one byte short of Length: %d, want 7", got)
	}
}

func certDER(t *testing.T, n int64) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseClientCAsBounds(t *testing.T) {
	one := certDER(t, 1)
	bundle := func(typ string, n int) []byte {
		var b []byte
		for i := 0; i < n; i++ {
			b = append(b, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: one})...)
		}
		return b
	}
	if _, err := ParseClientCAs(bundle("CERTIFICATE", maxClientCACerts)); err != nil {
		t.Fatalf("exactly %d certificates refused: %v", maxClientCACerts, err)
	}
	if _, err := ParseClientCAs(bundle("CERTIFICATE", maxClientCACerts+1)); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("one over the count: %v", err)
	}
	// A valid certificate under another PEM type: refused for its type, not
	// for failing to parse.
	if _, err := ParseClientCAs(bundle("TRUSTED CERTIFICATE", 1)); err == nil || !strings.Contains(err.Error(), "not a CERTIFICATE") {
		t.Fatalf("a TRUSTED CERTIFICATE block: %v", err)
	}
	// A CERTIFICATE block whose bytes are no certificate: the parse error.
	junk := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")})
	if _, err := ParseClientCAs(junk); err == nil || strings.Contains(err.Error(), "not a CERTIFICATE") {
		t.Fatalf("a CERTIFICATE block of junk: %v", err)
	}
	// Size: padding after the last block counts toward the bound.
	atMax := append(bundle("CERTIFICATE", 1), []byte(strings.Repeat("\n", maxClientCAFileBytes-len(bundle("CERTIFICATE", 1))))...)
	if _, err := ParseClientCAs(atMax); err != nil {
		t.Fatalf("a file of exactly %d bytes refused: %v", maxClientCAFileBytes, err)
	}
	if _, err := ParseClientCAs(append(atMax, '\n')); err == nil || !strings.Contains(err.Error(), "over") {
		t.Fatalf("a file one byte over: %v", err)
	}
}

func TestListenQUICBindFailureAndNoCertificate(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := ListenQUIC(pc.LocalAddr().String(), &tls.Config{}); err == nil {
		t.Fatal("listened on a UDP port that is taken")
	}
	if _, err := ListenQUIC("not an address", &tls.Config{}); err == nil {
		t.Fatal("listened on a malformed address")
	}
}
