//go:build !noquic

package smb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "files.test"},
		DNSNames:  []string{"files.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func listen(t *testing.T, opts ...QUICOption) (*quicListener, *tls.Config) {
	t.Helper()
	cert, pool := selfSigned(t)
	ln, err := ListenQUIC("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.(*quicListener), &tls.Config{RootCAs: pool, ServerName: "files.test", NextProtos: []string{"smb"}}
}

// RFC 9000 8.1.2: above the rate, an Initial from an unvalidated address is
// answered with a Retry; the client takes it and the handshake still completes.
func TestRetryEngagesUnderLoadAndNotBefore(t *testing.T) {
	l, conf := listen(t, WithQUICRetryRate(3))
	dial := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		qc, err := quic.DialAddr(ctx, l.Addr().String(), conf, nil)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		qc.CloseWithError(0, "")
	}
	for i := 0; i < 3; i++ {
		dial()
	}
	if n := l.retries.Load(); n != 0 {
		t.Fatalf("%d Retry before the rate was reached", n)
	}
	for i := 0; i < 5; i++ {
		dial()
	}
	if l.retries.Load() == 0 {
		t.Fatal("no Retry after 8 handshakes in a second at a rate of 3")
	}
}

// A peer that finishes the handshake and opens no stream holds a slot for
// quicStreamWait and is then closed with an application error.
func TestAPeerThatOpensNoStreamIsLetGo(t *testing.T) {
	old := quicStreamWait
	quicStreamWait = 300 * time.Millisecond
	t.Cleanup(func() { quicStreamWait = old })
	l, conf := listen(t, WithQUICMaxConnections(2))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, l.Addr().String(), conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer qc.CloseWithError(0, "")
	if len(l.slots) != 1 {
		// The accept loop may not have run yet.
		time.Sleep(100 * time.Millisecond)
	}
	<-qc.Context().Done()
	var ae *quic.ApplicationError
	if err := context.Cause(qc.Context()); !asAppErr(err, &ae) || ae.ErrorCode != quicErrNoStrm {
		t.Fatalf("closed with %v, want application error %d", err, quicErrNoStrm)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(l.slots); n != 0 {
		t.Fatalf("%d slots still held", n)
	}
}

func asAppErr(err error, target **quic.ApplicationError) bool {
	ae, ok := err.(*quic.ApplicationError)
	if ok {
		*target = ae
	}
	return ok
}

func TestListenQUICNeedsATLSConfig(t *testing.T) {
	if _, err := ListenQUIC("127.0.0.1:0", nil); err == nil {
		t.Fatal("accepted a nil tls.Config")
	}
}
