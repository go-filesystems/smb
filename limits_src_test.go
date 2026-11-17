package smb

import (
	"net"
	"testing"
)

type addrConn struct {
	net.Conn
	addr net.Addr
}

func (a addrConn) RemoteAddr() net.Addr { return a.addr }

func fromIP(s *Server, ip string) *conn {
	a, _ := net.Pipe()
	c := newConn(s, addrConn{a, &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}})
	c.counted.Store(true)
	return c
}

func TestSourceKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7:445":            "192.0.2.7",
		"[2001:db8:1:2:aaaa::1]:5": "2001:db8:1:2::",
		"[2001:db8:1:2:bbbb::9]:5": "2001:db8:1:2::",
		"[2001:db8:1:3::1]:5":      "2001:db8:1:3::",
	} {
		a, _ := net.ResolveTCPAddr("tcp", in)
		if got := sourceKey(a); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

// One source flooding fills its own caps and cannot lock out another; the
// counters go back to zero as connections end.
func TestOneSourceCannotLockOutAnother(t *testing.T) {
	s := limitedServer(-1, -1)
	s.MaxConnectionsPerSource, s.MaxPreAuthPerSource = 6, 4
	var flood []*conn
	for i := 0; i < 20; i++ {
		c := fromIP(s, "198.51.100.9")
		if s.admit(c) {
			flood = append(flood, c)
		}
	}
	if len(flood) != 4 {
		t.Fatalf("the flooding source holds %d, want its pre-auth cap, 4", len(flood))
	}
	other := fromIP(s, "203.0.113.5")
	if !s.admit(other) {
		t.Fatal("a second source was locked out by the first")
	}
	// Authenticating frees pre-auth room but not total room: 6 in all.
	for _, c := range flood {
		c.markAuthenticated()
	}
	n := 0
	for i := 0; i < 10; i++ {
		c := fromIP(s, "198.51.100.9")
		if s.admit(c) {
			flood = append(flood, c)
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d more admitted from the flooding source, want 2 (6 in all)", n)
	}
	for _, c := range append(flood, other) {
		s.release(c)
	}
	if len(s.srcTotal) != 0 || len(s.srcPre) != 0 || s.preAuth != 0 {
		t.Errorf("counters did not return to zero: %v %v %d", s.srcTotal, s.srcPre, s.preAuth)
	}
}

// Logging off the last session returns to the per-source pre-auth count too.
func TestPerSourceCountsFollowAuthentication(t *testing.T) {
	s := limitedServer(-1, -1)
	c := fromIP(s, "198.51.100.1")
	s.admit(c)
	if s.srcPre["198.51.100.1"] != 1 {
		t.Fatal("not counted")
	}
	c.markAuthenticated()
	if len(s.srcPre) != 0 {
		t.Errorf("still counted pre-auth: %v", s.srcPre)
	}
	c.markUnauthenticated()
	if s.srcPre["198.51.100.1"] != 1 {
		t.Errorf("not counted again: %v", s.srcPre)
	}
	s.release(c)
	if len(s.srcPre) != 0 || len(s.srcTotal) != 0 {
		t.Errorf("left behind: %v %v", s.srcPre, s.srcTotal)
	}
}
