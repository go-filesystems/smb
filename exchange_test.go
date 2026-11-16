package smb

import (
	"encoding/binary"
	"testing"
)

// Authentications in progress are keyed by the session id the server gave each, so
// one connection can have several at once and none can overwrite another.

func exchangeConn(t *testing.T, dialect uint16) *conn {
	t.Helper()
	c := newConn(New(), nil)
	c.dialect = dialect
	if dialect == dialect311 {
		c.preauth = preauthExtend(preauthStart(), []byte("negotiate"))
	}
	c.srv.AddUser("alice", "hunter2")
	c.srv.AddUser("mallory", "pw")
	return c
}

type setupper struct {
	t    *testing.T
	c    *conn
	next uint64
}

func (s *setupper) leg1(sid uint64) uint64 {
	s.t.Helper()
	r := &requester{c: s.c, next: s.next}
	out, err := s.c.dispatchChain(r.setup(sid, ntlmType1(), false))
	s.next = r.next
	if err != nil || statusOf(s.t, out) != statusMoreProcessing {
		s.t.Fatalf("leg one: %v %#x", err, statusOf(s.t, out))
	}
	return binary.LittleEndian.Uint64(out[offSessionID:])
}

func (s *setupper) leg2(sid uint64, user, password string) uint32 {
	s.t.Helper()
	ex := s.c.exchanges[sid]
	var ch *challenge
	if ex != nil {
		ch = ex.challenge
	} else {
		ch = &challenge{} // an exchange that is gone: any token will do
	}
	r := &requester{c: s.c, next: s.next}
	out, err := s.c.dispatchChain(r.setup(sid, ntlmType3(ch, user, password), false))
	s.next = r.next
	if err != nil {
		s.t.Fatal(err)
	}
	return statusOf(s.t, out)
}

// The injected request of the issue: an unsigned SESSION_SETUP with SessionId 0 in
// the middle of somebody else's login. It used to overwrite the one challenge the
// connection kept, and the legitimate second leg then failed.
func TestAnInjectedSessionSetupCannotOverwriteALoginInProgress(t *testing.T) {
	for _, dialect := range []uint16{dialect210, dialect302, dialect311} {
		s := &setupper{t: t, c: exchangeConn(t, dialect)}
		alice := s.leg1(0)
		attacker := s.leg1(0) // injected, unsigned, SessionId 0
		if attacker == alice {
			t.Fatalf("%s: the injected exchange was given the legitimate one's id", dialectName(dialect))
		}
		if st := s.leg2(alice, "alice", "hunter2"); st != statusSuccess {
			t.Errorf("%s: the legitimate login failed after the injection: %#x", dialectName(dialect), st)
		}
		if s.c.sessions[alice] == nil || s.c.sessions[alice].user != "alice" {
			t.Errorf("%s: alice has no session", dialectName(dialect))
		}
		// The injected exchange is its own: it can be finished, or left.
		if s.c.exchanges[attacker] == nil {
			t.Errorf("%s: finishing one login ended the other", dialectName(dialect))
		}
	}
}

// Two logins in flight finish in either order, each with its own session and its
// own keys (on 3.1.1 each has its own pre-authentication hash).
func TestInterleavedLoginsBothComplete(t *testing.T) {
	for _, dialect := range []uint16{dialect302, dialect311} {
		for _, reverse := range []bool{false, true} {
			s := &setupper{t: t, c: exchangeConn(t, dialect)}
			a := s.leg1(0)
			b := s.leg1(0)
			first, second := a, b
			firstUser, secondUser := "alice", "mallory"
			firstPw, secondPw := "hunter2", "pw"
			if reverse {
				first, second = b, a
				firstUser, secondUser = "mallory", "alice"
				firstPw, secondPw = "pw", "hunter2"
				// b is mallory's in this ordering: the users follow the finish order.
			}
			if st := s.leg2(first, firstUser, firstPw); st != statusSuccess {
				t.Fatalf("%s: first to finish: %#x", dialectName(dialect), st)
			}
			if st := s.leg2(second, secondUser, secondPw); st != statusSuccess {
				t.Fatalf("%s: second to finish: %#x", dialectName(dialect), st)
			}
			if len(s.c.sessions) != 2 || len(s.c.exchanges) != 0 {
				t.Errorf("%s: %d sessions, %d exchanges left", dialectName(dialect), len(s.c.sessions), len(s.c.exchanges))
			}
			ka, kb := s.c.sessions[a].signingKey, s.c.sessions[b].signingKey
			if string(ka) == string(kb) {
				t.Errorf("%s: the two sessions have the same signing key", dialectName(dialect))
			}
		}
	}
}

// What a connection may have in progress is bounded, the oldest going first.
func TestPendingExchangesAreBounded(t *testing.T) {
	s := &setupper{t: t, c: exchangeConn(t, dialect302)}
	var ids []uint64
	for i := 0; i < maxPendingExchanges+10; i++ {
		ids = append(ids, s.leg1(0))
		if n := len(s.c.exchanges); n > maxPendingExchanges {
			t.Fatalf("%d exchanges in progress after %d started, cap %d", n, i+1, maxPendingExchanges)
		}
	}
	if len(s.c.exchanges) != maxPendingExchanges || len(s.c.exchangeOrder) != maxPendingExchanges {
		t.Errorf("%d/%d held, want %d", len(s.c.exchanges), len(s.c.exchangeOrder), maxPendingExchanges)
	}
	// The oldest were dropped: their second leg fails; the newest finish.
	if st := s.leg2(ids[0], "alice", "hunter2"); st != statusUserSessionDeleted {
		t.Errorf("an exchange pushed out by newer ones answered %#x, want USER_SESSION_DELETED (the id is no longer one it knows)", st)
	}
	if st := s.leg2(ids[len(ids)-1], "alice", "hunter2"); st != statusSuccess {
		t.Errorf("the newest exchange: %#x", st)
	}
}

// A refused login ends its exchange, and a second leg with no exchange behind it
// is refused rather than answered from some other state.
func TestAFailedLoginEndsItsExchange(t *testing.T) {
	s := &setupper{t: t, c: exchangeConn(t, dialect302)}
	id := s.leg1(0)
	if st := s.leg2(id, "alice", "wrong"); st != statusLogonFailure {
		t.Fatalf("a wrong password: %#x", st)
	}
	if len(s.c.exchanges) != 0 {
		t.Error("the refused exchange was kept")
	}
	if st := s.leg2(id, "alice", "hunter2"); st != statusUserSessionDeleted {
		t.Errorf("a second leg on an exchange that had ended answered %#x", st)
	}
	if len(s.c.sessions) != 0 {
		t.Error("a session exists")
	}
}
