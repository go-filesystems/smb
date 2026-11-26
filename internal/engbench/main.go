// Command engbench measures the two SMB client engines (cloudsoda/go-smb2 and
// the in-house one in package smb) against the same server, interleaved round
// by round, on one core.
//
//	engbench -mode seed -path DIR -dirs 1000 -files 100 -big 268435456
//	engbench -mode run  -addr 127.0.0.1:1445 -user alice -pass-file F -share data -rounds 5
//
// The password is read from a file, never from argv.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/cloudsoda/go-smb2"

	smb "github.com/go-filesystems/smb"
)

func main() {
	mode := flag.String("mode", "run", "seed or run")
	path := flag.String("path", "", "seed: directory to fill")
	dirs := flag.Int("dirs", 1000, "seed: directories")
	files := flag.Int("files", 100, "seed: files per directory")
	big := flag.Int64("big", 256<<20, "seed: size of big.bin")
	addr := flag.String("addr", "127.0.0.1:445", "server")
	user := flag.String("user", "alice", "user")
	passFile := flag.String("pass-file", "", "file holding the password")
	share := flag.String("share", "data", "share")
	rounds := flag.Int("rounds", 5, "interleaved rounds")
	flag.Parse()
	var err error
	switch *mode {
	case "seed":
		err = seed(*path, *dirs, *files, *big)
	default:
		err = run(*addr, *user, *passFile, *share, *rounds)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "engbench:", err)
		os.Exit(1)
	}
}

func seed(root string, dirs, files int, big int64) error {
	if root == "" {
		return fmt.Errorf("-path is required")
	}
	for d := range dirs {
		dp := filepath.Join(root, fmt.Sprintf("d%04d", d))
		if err := os.MkdirAll(dp, 0o755); err != nil {
			return err
		}
		for f := range files {
			if err := os.WriteFile(filepath.Join(dp, fmt.Sprintf("f%04d", f)), []byte("x"), 0o644); err != nil {
				return err
			}
		}
	}
	f, err := os.Create(filepath.Join(root, "big.bin"))
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(big)
}

type engine struct {
	name string
	du   func(ctx context.Context) (n int, bytes int64, err error)
	read func(ctx context.Context) (int64, error)
}

func run(addr, user, passFile, share string, rounds int) error {
	pw, err := os.ReadFile(passFile)
	if err != nil {
		return err
	}
	pass := strings.TrimSpace(string(pw))
	host, _, _ := net.SplitHostPort(addr)
	ctx := context.Background()

	// go-smb2
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: user, Password: pass}}
	s2, err := d.DialConn(ctx, nc, addr)
	if err != nil {
		return fmt.Errorf("go-smb2: %w", err)
	}
	defer s2.Logoff()
	sh2, err := s2.Mount(share)
	if err != nil {
		return err
	}
	var walk2 func(p string) (int, int64, error)
	walk2 = func(p string) (int, int64, error) {
		es, err := sh2.WithContext(ctx).ReadDir(p)
		if err != nil {
			return 0, 0, err
		}
		n, b := 0, int64(0)
		for _, e := range es {
			if e.IsDir() {
				cn, cb, err := walk2(p + "/" + e.Name())
				if err != nil {
					return 0, 0, err
				}
				n, b = n+cn, b+cb
				continue
			}
			n++
			b += e.Size()
		}
		return n, b, nil
	}

	// own engine
	nc2, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	c, err := smb.ClientDial(ctx, nc2, smb.ClientOptions{User: user, Password: pass, Host: host})
	if err != nil {
		return fmt.Errorf("own engine: %w", err)
	}
	defer c.Close()
	sh, err := c.Mount(ctx, share)
	if err != nil {
		return err
	}
	var walk func(p string) (int, int64, error)
	walk = func(p string) (int, int64, error) {
		es, err := sh.ReadDir(ctx, p)
		if err != nil {
			return 0, 0, err
		}
		n, b := 0, int64(0)
		for _, e := range es {
			if e.IsDir() {
				cn, cb, err := walk(p + "/" + e.Name)
				if err != nil {
					return 0, 0, err
				}
				n, b = n+cn, b+cb
				continue
			}
			n++
			b += e.Size
		}
		return n, b, nil
	}
	fmt.Printf("own engine: dialect %#x, %s, encrypted=%v, signing=%s\n", c.Dialect(), c.CipherName(), c.Encrypted(), c.Signing())

	engines := []engine{
		{"go-smb2", func(context.Context) (int, int64, error) { return walk2(".") },
			func(context.Context) (int64, error) {
				f, err := sh2.Open("big.bin")
				if err != nil {
					return 0, err
				}
				defer f.Close()
				return io.Copy(io.Discard, f)
			}},
		{"own", func(context.Context) (int, int64, error) { return walk(".") },
			func(context.Context) (int64, error) {
				f, err := sh.Open(ctx, "big.bin")
				if err != nil {
					return 0, err
				}
				defer f.Close()
				return io.Copy(io.Discard, f)
			}},
	}
	runtime.GOMAXPROCS(1)
	type sample struct {
		dur     time.Duration
		mallocs uint64
		n       int
	}
	res := map[string][]sample{}
	for r := range rounds {
		order := engines
		if r%2 == 1 {
			order = []engine{engines[1], engines[0]}
		}
		for _, e := range order {
			for _, kind := range []string{"du", "read"} {
				runtime.GC()
				var m0, m1 runtime.MemStats
				runtime.ReadMemStats(&m0)
				t0 := time.Now()
				var n int
				var err error
				if kind == "du" {
					n, _, err = e.du(ctx)
				} else {
					var nb int64
					nb, err = e.read(ctx)
					n = int(nb >> 20)
				}
				dt := time.Since(t0)
				runtime.ReadMemStats(&m1)
				if err != nil {
					return fmt.Errorf("%s %s: %w", e.name, kind, err)
				}
				k := e.name + "/" + kind
				res[k] = append(res[k], sample{dt, m1.Mallocs - m0.Mallocs, n})
			}
		}
	}
	var out bytes.Buffer
	for _, k := range []string{"go-smb2/du", "own/du", "go-smb2/read", "own/read"} {
		ss := res[k]
		slices.SortFunc(ss, func(a, b sample) int { return int(a.dur - b.dur) })
		med := ss[len(ss)/2]
		fmt.Fprintf(&out, "%-14s median %10v  mallocs %9d  units %d  (best %v, %d rounds)\n", k, med.dur.Round(time.Millisecond), med.mallocs, med.n, ss[0].dur.Round(time.Millisecond), len(ss))
	}
	fmt.Print(out.String())
	return nil
}
