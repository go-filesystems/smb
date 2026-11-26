//go:build !noquic

package smb_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/go-filesystems/go-smb2"
	"github.com/quic-go/quic-go"

	fssmb "github.com/go-filesystems/smb"
)

// A test CA and the certificates it signs: a server one with a DNS SAN (no IP
// SAN, as Microsoft Learn requires) and client ones with EKU Client Authentication.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t testing.TB, name string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) issue(t testing.TB, cn string, eku x509.ExtKeyUsage, dns ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		DNSNames:  dns,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// qconn is a quic stream as the net.Conn go-smb2 dials over.
type qconn struct {
	qc *quic.Conn
	st *quic.Stream
}

func (c *qconn) Read(p []byte) (int, error)         { return c.st.Read(p) }
func (c *qconn) Write(p []byte) (int, error)        { return c.st.Write(p) }
func (c *qconn) LocalAddr() net.Addr                { return c.qc.LocalAddr() }
func (c *qconn) RemoteAddr() net.Addr               { return c.qc.RemoteAddr() }
func (c *qconn) SetDeadline(t time.Time) error      { return c.st.SetDeadline(t) }
func (c *qconn) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *qconn) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }
func (c *qconn) Close() error {
	c.st.Close()
	return c.qc.CloseWithError(0, "")
}

type quicFixture struct {
	addr  string
	srv   *fssmb.Server
	ca    *testCA
	roots *x509.CertPool
}

func startQUIC(t testing.TB, tune func(*tls.Config), opts ...fssmb.QUICOption) *quicFixture {
	t.Helper()
	t.Cleanup(fssmb.SetQUICHandshakeTimeout(60 * time.Second))
	ca := newCA(t, "test ca")
	conf := &tls.Config{Certificates: []tls.Certificate{ca.issue(t, "files.test", x509.ExtKeyUsageServerAuth, "files.test")}}
	if tune != nil {
		tune(conf)
	}
	ln, err := fssmb.ListenQUIC("127.0.0.1:0", conf, opts...)
	if err != nil {
		t.Fatal(err)
	}
	srv := fssmb.New()
	srv.AddUser("alice", "hunter2")
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	return &quicFixture{addr: ln.Addr().String(), srv: srv, ca: ca, roots: roots}
}

func (f *quicFixture) clientConf(mut func(*tls.Config)) *tls.Config {
	c := &tls.Config{RootCAs: f.roots, ServerName: "files.test", NextProtos: []string{"smb"}}
	if mut != nil {
		mut(c)
	}
	return c
}

func (f *quicFixture) dialQUIC(t testing.TB, conf *tls.Config) (*qconn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, f.addr, conf, &quic.Config{MaxIdleTimeout: 60 * time.Second, HandshakeIdleTimeout: 60 * time.Second})
	if err != nil {
		return nil, err
	}
	st, err := qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &qconn{qc, st}, nil
}

// mountOver authenticates with NTLM over a QUIC stream and mounts the share.
func (f *quicFixture) mountOver(t testing.TB, conf *tls.Config) (*smb2.Share, func(), error) {
	nc, err := f.dialQUIC(t, conf)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "alice", Password: "hunter2"}}
	s, err := d.DialConn(ctx, nc, f.addr)
	if err != nil {
		cancel()
		nc.Close()
		return nil, nil, err
	}
	sh, err := s.Mount("data")
	if err != nil {
		cancel()
		s.Logoff()
		return nil, nil, err
	}
	return sh, func() { sh.Umount(); s.Logoff(); cancel() }, nil
}

func TestQUICMountsAndMovesData(t *testing.T) {
	f := startQUIC(t, nil)
	fs := &widestReadFS{memFS: newMemFS(true)}
	want := bytes.Repeat([]byte("0123456789abcdef"), 1<<20/16)
	fs.WriteFile("/big.bin", want, 0o644)
	if err := f.srv.Share("data", fs); err != nil {
		t.Fatal(err)
	}
	sh, done, err := f.mountOver(t, f.clientConf(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	got, err := sh.ReadFile("big.bin")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("read back %d bytes, %v", len(got), err)
	}
	// [MS-SMB2] 3.3.5.4: no multi-credit over QUIC, so no request is wider than a credit.
	if w := fs.widest.Load(); w > 64<<10 {
		t.Fatalf("a read of %d bytes over QUIC: multi-credit was not withheld", w)
	}
	payload := bytes.Repeat([]byte("w"), 300<<10)
	if err := sh.WriteFile("up.bin", payload, 0o644); err != nil {
		t.Fatal(err)
	}
	back, err := sh.ReadFile("up.bin")
	if err != nil || !bytes.Equal(back, payload) {
		t.Fatalf("round trip: %d bytes, %v", len(back), err)
	}
	if err := sh.Remove("up.bin"); err != nil {
		t.Fatal(err)
	}
}

func TestQUICOnlyTLS13AndSMBALPN(t *testing.T) {
	f := startQUIC(t, nil)
	for name, mut := range map[string]func(*tls.Config){
		"h3 ALPN": func(c *tls.Config) { c.NextProtos = []string{"h3"} },
		"no ALPN": func(c *tls.Config) { c.NextProtos = nil },
	} {
		if nc, err := f.dialQUIC(t, f.clientConf(mut)); err == nil {
			nc.Close()
			t.Errorf("%s: handshake succeeded", name)
		}
	}
	// QUIC requires TLS 1.3 on the client side too: a TLS 1.2 ceiling cannot even start.
	if nc, err := f.dialQUIC(t, f.clientConf(func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 })); err == nil {
		nc.Close()
		t.Error("TLS 1.2 handshake succeeded")
	}
}

func TestQUICOneStreamAndNoUnidirectional(t *testing.T) {
	f := startQUIC(t, nil)
	nc, err := f.dialQUIC(t, f.clientConf(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	nc.st.Write([]byte{0}) // let the server accept the first stream
	time.Sleep(200 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	if s2, err := nc.qc.OpenStreamSync(ctx); err == nil {
		s2.Write([]byte{0})
		t.Error("a second bidirectional stream was granted")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel2()
	if u, err := nc.qc.OpenUniStreamSync(ctx2); err == nil {
		u.Write([]byte{0})
		t.Error("a unidirectional stream was granted")
	}
}

func TestQUICClientCertificateModes(t *testing.T) {
	// Kerberos only (the default): no certificate asked, none needed.
	f := startQUIC(t, nil)
	f.srv.Share("data", newMemFS(true))
	if _, done, err := f.mountOver(t, f.clientConf(nil)); err != nil {
		t.Fatalf("default mode, no certificate: %v", err)
	} else {
		done()
	}

	// Required: verified against the CA file.
	clientCA := newCA(t, "smb clients")
	rogueCA := newCA(t, "rogue")
	g := startQUIC(t, func(c *tls.Config) {
		if err := fssmb.RequireClientCertificate(c, clientCA.pem); err != nil {
			t.Fatal(err)
		}
	})
	g.srv.Share("data", newMemFS(true))
	good := clientCA.issue(t, "alice-laptop", x509.ExtKeyUsageClientAuth)
	wrongEKU := clientCA.issue(t, "server-key-as-client", x509.ExtKeyUsageServerAuth)
	rogue := rogueCA.issue(t, "mallory", x509.ExtKeyUsageClientAuth)
	for name, tc := range map[string]struct {
		certs []tls.Certificate
		ok    bool
	}{
		"none":               {nil, false},
		"from another CA":    {[]tls.Certificate{rogue}, false},
		"wrong key usage":    {[]tls.Certificate{wrongEKU}, false},
		"from the client CA": {[]tls.Certificate{good}, true},
	} {
		_, done, err := g.mountOver(t, g.clientConf(func(c *tls.Config) { c.Certificates = tc.certs }))
		if tc.ok != (err == nil) {
			t.Errorf("%s: err=%v, want success=%v", name, err, tc.ok)
		}
		if done != nil {
			done()
		}
	}
}

// A peer that sends nothing after the handshake holds a slot for a bounded time
// only, and the cap on connections refuses the one over it.
func TestQUICConnectionCap(t *testing.T) {
	f := startQUIC(t, nil, fssmb.WithQUICMaxConnections(1))
	f.srv.Share("data", newMemFS(true))
	first, err := f.dialQUIC(t, f.clientConf(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	first.st.Write([]byte{0})
	time.Sleep(200 * time.Millisecond)
	second, err := f.dialQUIC(t, f.clientConf(nil))
	if err != nil {
		return // refused in the handshake: fine
	}
	defer second.Close()
	second.st.Write([]byte{0})
	second.st.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(second.st); err == nil {
		t.Fatal("a connection over the cap was served")
	} else if _, ok := err.(*quic.ApplicationError); !ok {
		t.Logf("second connection ended with %v", err)
	}
}
