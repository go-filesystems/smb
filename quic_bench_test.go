//go:build !noquic

package smb_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"

	fssmb "github.com/go-filesystems/smb"
)

// The same server, the same client, the same share over TCP and over QUIC.
// Run interleaved on one core:
//
//	go test -run '^$' -bench 'Transport' -benchmem -cpu 1 -count 8 .
//
// Over TCP a read of 1 MiB is one multi-credit request; over QUIC
// [MS-SMB2] 3.3.5.4 forbids multi-credit, so it is sixteen 64 KiB requests.
func benchMount(b *testing.B, quicT bool) (*smb2.Share, func()) {
	b.Helper()
	fs := newMemFS(true)
	fs.WriteFile("/big.bin", bytes.Repeat([]byte("0123456789abcdef"), 1<<20/16), 0o644)
	var sh *smb2.Share
	var done func()
	if quicT {
		f := startQUIC(b, nil)
		if err := f.srv.Share("data", fs); err != nil {
			b.Fatal(err)
		}
		var err error
		sh, done, err = f.mountOver(b, f.clientConf(nil))
		if err != nil {
			b.Fatal(err)
		}
		return sh, done
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	srv := fssmb.New()
	srv.AddUser("alice", "hunter2")
	if err := srv.Share("data", fs); err != nil {
		b.Fatal(err)
	}
	go srv.Serve(ln)
	nc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "alice", Password: "hunter2"}}
	s, err := d.DialConn(ctx, nc, ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	sh, err = s.Mount("data")
	if err != nil {
		b.Fatal(err)
	}
	return sh, func() { sh.Umount(); s.Logoff(); cancel(); srv.Close() }
}

func BenchmarkTransportRead1MiB(b *testing.B) {
	for _, tr := range []struct {
		name string
		quic bool
	}{{"tcp", false}, {"quic", true}} {
		b.Run(tr.name, func(b *testing.B) {
			sh, done := benchMount(b, tr.quic)
			defer done()
			b.SetBytes(1 << 20)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				f, err := sh.Open("big.bin")
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
}

func BenchmarkTransportWrite1MiB(b *testing.B) {
	payload := bytes.Repeat([]byte("w"), 1<<20)
	for _, tr := range []struct {
		name string
		quic bool
	}{{"tcp", false}, {"quic", true}} {
		b.Run(tr.name, func(b *testing.B) {
			sh, done := benchMount(b, tr.quic)
			defer done()
			b.SetBytes(1 << 20)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := sh.WriteFile("w.bin", payload, 0o644); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTransportStat(b *testing.B) {
	for _, tr := range []struct {
		name string
		quic bool
	}{{"tcp", false}, {"quic", true}} {
		b.Run(tr.name, func(b *testing.B) {
			sh, done := benchMount(b, tr.quic)
			defer done()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := sh.Stat("big.bin"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
