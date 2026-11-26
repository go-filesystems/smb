package client

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	fssmb "github.com/go-filesystems/smb"
)

func FuzzParseUNC(f *testing.F) {
	for _, s := range []string{"//h/s/a", `\\h\s`, "//[::1]:445/s/x/../y", "//h:1/s", "", "//", "//h/s/\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		tg, err := ParseUNC(s)
		if err != nil {
			return
		}
		// What is accepted must be safe to send: no traversal, no separator
		// inside a component, no control character, bounded.
		if tg.Host == "" || tg.Share == "" || tg.Port == "" {
			t.Fatalf("%q: empty field in %+v", s, tg)
		}
		if tg.Path != "" {
			parts := strings.Split(tg.Path, "/")
			if len(parts) > maxPathDeep {
				t.Fatalf("%q: too deep", s)
			}
			for _, c := range parts {
				if c == "" || c == "." || c == ".." || strings.ContainsAny(c, `\`) {
					t.Fatalf("%q: bad component %q in %q", s, c, tg.Path)
				}
			}
		}
		for _, r := range s {
			if r < 0x20 {
				t.Fatalf("%q: control character accepted", s)
			}
		}
	})
}

func FuzzParseCredentials(f *testing.F) {
	for _, s := range []string{"username=a\npassword=b\n", "# c\nuser=x\n", "username=a\r\ndomain=D\r\n", "=\n", "username=a\nusername=b"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseCredentials(b)
		if err == nil && c.User == "" {
			t.Fatal("accepted with no user")
		}
		if err != nil && c != (Credentials{}) {
			t.Fatal("a refusal returned credentials")
		}
	})
}

// The volume sizes a server names: whatever the wire holds, the product must
// not overflow and a refusal must be ErrBadFSInfo.
func FuzzFsInfoOf(f *testing.F) {
	f.Add(uint64(4096), uint64(1000), uint64(500), uint64(400))
	f.Add(uint64(1), ^uint64(0), uint64(0), uint64(0))
	f.Fuzz(func(t *testing.T, unit, total, free, avail uint64) {
		fi, err := fsInfoOf(unit, total, free, avail)
		if err != nil {
			return
		}
		const maxInt = 1<<63 - 1
		if fi.Total/unit != total || fi.Free/unit != free || fi.Avail/unit != avail || fi.Total > maxInt || fi.Free > maxInt || fi.Avail > maxInt {
			t.Fatalf("overflow: %d %d %d %d -> %+v", unit, total, free, avail, fi)
		}
	})
}

// recorder keeps every byte the server sent.
type recorder struct {
	net.Conn
	mu  *sync.Mutex
	got *[]byte
}

func (r recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.mu.Lock()
	*r.got = append(*r.got, p[:n]...)
	r.mu.Unlock()
	return n, err
}

// frames splits direct-TCP framed bytes (0x00, 3-byte length) into bodies.
func frames(b []byte) [][]byte {
	var out [][]byte
	for len(b) >= 4 {
		n := int(binary.BigEndian.Uint32(b[:4]) & 0xffffff)
		if len(b) < 4+n {
			break
		}
		out = append(out, b[4:4+n])
		b = b[4+n:]
	}
	return out
}

// FuzzDialHostileServer plays a server that answers the client's first three
// requests (negotiate, session setup, session setup) with arbitrary bodies.
// Every decoder of a server response runs on them. The client must return, in
// bounded time, without a panic: an error or a session, never a hang or a crash.
// The seeds are the REAL responses of this module's server.
func FuzzDialHostileServer(f *testing.F) {
	srv := fssmb.New()
	srv.AddUser("alice", "hunter2")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()
	var (
		rec   []byte
		recMu sync.Mutex
	)
	tg := Target{Host: "127.0.0.1", Port: "445", Share: "x"}
	o := Options{
		Auth: NTLM{Credentials: Credentials{User: "alice", Password: "hunter2"}},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
			return recorder{c, &recMu, &rec}, err
		},
	}
	if s, err := Dial(context.Background(), tg, o); err == nil {
		s.Close()
	}
	recMu.Lock()
	fr := frames(append([]byte(nil), rec...))
	recMu.Unlock()
	for len(fr) < 3 {
		fr = append(fr, nil)
	}
	f.Add(fr[0], fr[1], fr[2])
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(fr[0], []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, a, b, c []byte) {
		if len(a)+len(b)+len(c) > 1<<16 {
			return
		}
		hl, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		defer hl.Close()
		go func() {
			conn, err := hl.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			for _, body := range [][]byte{a, b, c} {
				var h [4]byte
				if _, err := io.ReadFull(conn, h[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint32(h[:]) & 0xffffff)
				if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
					return
				}
				var w [4]byte
				binary.BigEndian.PutUint32(w[:], uint32(len(body)))
				if _, err := conn.Write(append(w[:], body...)); err != nil {
					return
				}
			}
		}()
		ho := Options{
			Auth:           o.Auth,
			ConnectTimeout: 300 * time.Millisecond,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, hl.Addr().String())
			},
		}
		start := time.Now()
		s, err := Dial(context.Background(), tg, ho)
		if err == nil {
			s.Close()
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("Dial took %v", d)
		}
	})
}
