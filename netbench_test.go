//go:build !noquic

package smb_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/go-filesystems/go-smb2"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/quic-go/quic-go"
)

// A benchmark of a REAL server (fileshare) over TCP and over QUIC, with
// Kerberos from a ccache, for #78: loopback hides the network, this runs across
// one. Compile once (`go test -c`), copy the binary to the client host, then
//
//	NETBENCH_CCACHE=/tmp/krb5cc_1000 NETBENCH_KRB5=/path/krb5.conf \
//	NETBENCH_SPN=cifs/fs.example.org NETBENCH_SHARE=docs \
//	NETBENCH_TCP=10.80.0.1:445 NETBENCH_QUIC=192.168.1.67:443 NETBENCH_SNI=fs.example.org \
//	./smb.test -test.run '^$' -test.bench NetTransport -test.benchmem -test.cpu 1 -test.count 8
//
// Each transport uses its own directory in the share (netbench-<pid>-<name>),
// removed when the sub-benchmark ends. A transport whose address is unset is
// skipped. The server must accept the ticket for NETBENCH_SPN.
var netBenchSeq int

type netEnv struct{ ccache, krb5, spn, share, tcp, quic, sni string }

func netEnvOf(b *testing.B) netEnv {
	e := netEnv{os.Getenv("NETBENCH_CCACHE"), os.Getenv("NETBENCH_KRB5"), os.Getenv("NETBENCH_SPN"),
		os.Getenv("NETBENCH_SHARE"), os.Getenv("NETBENCH_TCP"), os.Getenv("NETBENCH_QUIC"), os.Getenv("NETBENCH_SNI")}
	if e.ccache == "" || e.krb5 == "" || e.spn == "" || e.share == "" || (e.tcp == "" && e.quic == "") {
		b.Skip("NETBENCH_CCACHE, _KRB5, _SPN, _SHARE and _TCP or _QUIC are required")
	}
	return e
}

func (e netEnv) mount(b *testing.B, quicT bool) (*smb2.Share, func()) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	var nc net.Conn
	var addr string
	if quicT {
		addr = e.quic
		qc, err := quic.DialAddr(ctx, addr, &tls.Config{ServerName: e.sni, NextProtos: []string{"smb"}, MinVersion: tls.VersionTLS13},
			&quic.Config{MaxIdleTimeout: 60 * time.Second})
		if err != nil {
			b.Fatal(err)
		}
		st, err := qc.OpenStreamSync(ctx)
		if err != nil {
			b.Fatal(err)
		}
		nc = &qconn{qc, st}
	} else {
		addr = e.tcp
		c, err := net.Dial("tcp", addr)
		if err != nil {
			b.Fatal(err)
		}
		nc = c
	}
	cc, err := credentials.LoadCCache(e.ccache)
	if err != nil {
		b.Fatal(err)
	}
	cfg, err := config.Load(e.krb5)
	if err != nil {
		b.Fatal(err)
	}
	cl, err := client.NewFromCCache(cc, cfg, client.DisablePAFXFAST(true))
	if err != nil {
		b.Fatal(err)
	}
	d := &smb2.Dialer{Initiator: &smb2.Krb5Initiator{Client: cl, TargetSPN: e.spn}}
	s, err := d.DialConn(ctx, nc, addr)
	if err != nil {
		b.Fatal(err)
	}
	sh, err := s.Mount(e.share)
	if err != nil {
		b.Fatal(err)
	}
	return sh, func() { sh.Umount(); s.Logoff(); cancel() }
}

func netBench(b *testing.B, size int64, setup func(b *testing.B, sh *smb2.Share, dir string), body func(b *testing.B, sh *smb2.Share, dir string)) {
	e := netEnvOf(b)
	for _, tr := range []struct {
		name string
		quic bool
		addr string
	}{{"tcp", false, e.tcp}, {"quic", true, e.quic}} {
		if tr.addr == "" {
			continue
		}
		b.Run(tr.name, func(b *testing.B) {
			sh, done := e.mount(b, tr.quic)
			defer done()
			netBenchSeq++
			dir := fmt.Sprintf("netbench-%d-%s-%d", os.Getpid(), tr.name, netBenchSeq)
			if err := sh.Mkdir(dir, 0o755); err != nil {
				b.Fatal(err)
			}
			defer func() {
				if err := sh.RemoveAll(dir); err != nil {
					b.Logf("cleanup of %s failed: %v", dir, err)
				}
			}()
			if setup != nil {
				setup(b, sh, dir)
			}
			b.SetBytes(size)
			b.ReportAllocs()
			b.ResetTimer()
			body(b, sh, dir)
		})
	}
}

func BenchmarkNetTransportRead1MiB(b *testing.B) {
	netBench(b, 1<<20, func(b *testing.B, sh *smb2.Share, dir string) {
		if err := sh.WriteFile(dir+"/big.bin", bytes.Repeat([]byte("0123456789abcdef"), 1<<20/16), 0o644); err != nil {
			b.Fatal(err)
		}
	}, func(b *testing.B, sh *smb2.Share, dir string) {
		for i := 0; i < b.N; i++ {
			f, err := sh.Open(dir + "/big.bin")
			if err != nil {
				b.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, f); err != nil {
				b.Fatal(err)
			}
			f.Close()
		}
	})
}

func BenchmarkNetTransportWrite1MiB(b *testing.B) {
	payload := bytes.Repeat([]byte("w"), 1<<20)
	netBench(b, 1<<20, nil, func(b *testing.B, sh *smb2.Share, dir string) {
		for i := 0; i < b.N; i++ {
			if err := sh.WriteFile(dir+"/w.bin", payload, 0o644); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkNetTransportStat(b *testing.B) {
	netBench(b, 0, func(b *testing.B, sh *smb2.Share, dir string) {
		if err := sh.WriteFile(dir+"/s.bin", []byte("x"), 0o644); err != nil {
			b.Fatal(err)
		}
	}, func(b *testing.B, sh *smb2.Share, dir string) {
		for i := 0; i < b.N; i++ {
			if _, err := sh.Stat(dir + "/s.bin"); err != nil {
				b.Fatal(err)
			}
		}
	})
}
