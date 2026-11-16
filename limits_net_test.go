package smb_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"

	fssmb "github.com/go-filesystems/smb"
)

// The limits over real TCP.

func dialIdle(t *testing.T, addr string, n int) []net.Conn {
	t.Helper()
	var cs []net.Conn
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		cs = append(cs, c)
	}
	return cs
}

// held says how many of the connections the server still holds: a closed one
// reads EOF at once, a held one has nothing to say and the read times out. They
// are asked together, so the wait is one deadline and not one per connection.
func held(cs []net.Conn) int {
	var mu sync.Mutex
	var wg sync.WaitGroup
	n := 0
	for _, c := range cs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			if _, err := c.Read(make([]byte, 1)); err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					mu.Lock()
					n++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return n
}

func mounts(t *testing.T, addr string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "alice", Password: "hunter2"}}
	s, err := d.Dial(ctx, addr)
	if err != nil {
		return err
	}
	defer s.WithContext(ctx).Logoff()
	fs, err := s.Mount("disk")
	if err != nil {
		return err
	}
	fs.Umount()
	return nil
}

func TestAFloodOfIdleConnectionsIsBounded(t *testing.T) {
	addr, srv := serve(t)
	srv.MaxPreAuthConnections = 8
	srv.PreAuthTimeout = -1
	srv.Share("disk", newMemFS(true))
	flood := dialIdle(t, addr, 60)
	if got := held(flood); got != 8 {
		t.Fatalf("the server holds %d of 60 idle connections, want exactly the cap, 8", got)
	}
}

// The flood sits one below the cap: a client that logs in still gets the last
// place, uses it, and gives it back -- and with the flood AT the cap, it does not.
func TestALegitimateClientMountsWhileTheFloodSitsBelowTheCap(t *testing.T) {
	addr, srv := serve(t)
	srv.MaxPreAuthConnections = 8
	srv.PreAuthTimeout = -1
	srv.Share("disk", newMemFS(true))
	flood := dialIdle(t, addr, 7)
	if got := held(flood); got != 7 {
		t.Fatalf("the flood holds %d, want 7", got)
	}
	if err := mounts(t, addr); err != nil {
		t.Fatalf("a legitimate client could not mount with the flood at the cap minus one: %v", err)
	}
	// Its place was given back when it authenticated and went when it left: the
	// cap is full only of idle connections now.
	more := dialIdle(t, addr, 5)
	if got := held(more); got != 1 {
		t.Errorf("%d of 5 more were held, want the 1 place that is left", got)
	}
	if err := mounts(t, addr); err == nil {
		t.Error("a client mounted although the unauthenticated cap is full of idle connections")
	}
}

func TestTheTimeoutClosesASilentConnectionAndNotALoggedInOne(t *testing.T) {
	addr, srv := serve(t)
	srv.PreAuthTimeout = 150 * time.Millisecond
	mem := newMemFS(true)
	mem.WriteFile("/a.txt", []byte("still here"), 0o644)
	srv.Share("disk", mem)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "alice", Password: "hunter2"}}
	s, err := d.Dial(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer s.WithContext(ctx).Logoff()
	fs, err := s.Mount("disk")
	if err != nil {
		t.Fatal(err)
	}
	silent := dialIdle(t, addr, 1)[0]
	silent.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := silent.Read(make([]byte, 1)); err == nil {
		t.Fatal("the silent connection sent something")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the silent connection was still open after 5 s")
	}
	if took := time.Since(start); took < 100*time.Millisecond {
		t.Errorf("closed after %v, before the timeout", took)
	}
	// The logged-in client is well past the timeout by now, and works.
	if got, err := fs.ReadFile("a.txt"); err != nil || string(got) != "still here" {
		t.Errorf("the logged-in connection: %q %v", got, err)
	}
}

func TestTheTotalCapOverTCP(t *testing.T) {
	addr, srv := serve(t)
	srv.MaxConnections = 5
	srv.MaxPreAuthConnections = -1
	srv.PreAuthTimeout = -1
	srv.Share("disk", newMemFS(true))
	if got := held(dialIdle(t, addr, 12)); got != 5 {
		t.Fatalf("the server holds %d connections, want 5", got)
	}
}

var _ = fssmb.DefaultMaxConnections
