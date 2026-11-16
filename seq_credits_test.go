package smb

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// How many credits a client may hold unused is the server's policy
// ([MS-SMB2] 3.3.1.2), and it is bounded: a peer that asks for the most credits
// on every request, and never logs in, does not end up holding thousands.
func TestCreditsGrantedAreBounded(t *testing.T) {
	w := newSeqWindow()
	// A grant is never more than asked, never more than the room, and never zero.
	if got := w.allow(10, 64); got != 10 {
		t.Errorf("allow(10, 64) = %d", got)
	}
	if got := w.allow(500, 64); got != 53 { // the window holds 1 and 10 are reserved
		t.Errorf("allow(500, 64) with 10 reserved = %d, want the 53 that remain", got)
	}
	if got := w.allow(500, 64); got != 1 { // nothing left: one, so the client is never starved
		t.Errorf("allow with no room = %d, want 1", got)
	}
	w.release(64)
	if w.reserved != 0 {
		t.Errorf("%d reserved after releasing everything", w.reserved)
	}
	if got := w.allow(0, 64); got != 1 {
		t.Errorf("a request asking for none is granted %d, want 1", got)
	}
}

func TestAnAnonymousConnectionIsGrantedFewCredits(t *testing.T) {
	c := windowConn(t)
	for id := uint64(0); id < 300; id++ {
		m := echoWithID(id, 1)
		binary.LittleEndian.PutUint16(m[offCredits:], 512)
		out, err := c.dispatchChain(m)
		if err != nil {
			t.Fatalf("id %d: %v", id, err)
		}
		if st := statusOf(t, out); st != statusSuccess {
			t.Fatalf("id %d: %#x", id, st)
		}
		if held := c.seq.available(); held > creditCapAnonymous {
			t.Fatalf("after %d requests the client holds %d unused credits, cap %d", id+1, held, creditCapAnonymous)
		}
	}
	// With a session the cap is higher.
	c.sessions[1] = &session{user: "alice"}
	for id := uint64(300); id < 300+2*creditCapAuthenticated; id++ {
		m := echoWithID(id, 1)
		binary.LittleEndian.PutUint16(m[offCredits:], 512)
		if _, err := c.dispatchChain(m); err != nil {
			t.Fatalf("id %d: %v", id, err)
		}
		if held := c.seq.available(); held > creditCapAuthenticated {
			t.Fatalf("authenticated: %d unused credits held, cap %d", held, creditCapAuthenticated)
		}
	}
	if c.seq.available() <= creditCapAnonymous {
		t.Error("an authenticated connection was held to the anonymous cap")
	}
}

// An answer sent later grants nothing: its credits went out in the interim reply.
func TestTheCreditsOfAnAnswerSentLaterAreInTheInterimReply(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	c := sessionConn(t)
	c.nc = srv
	c.seq = newSeqWindow()
	op := &pendingOp{session: 1, asyncID: 3, cancel: make(chan struct{})}
	c.waiting[3] = op
	before := c.seq.limit
	reply := asyncResponse(header{command: cmdChangeNotify, messageID: 5, credits: 300}, statusSuccess, 3, 9)
	if binary.LittleEndian.Uint16(reply[offCredits:]) == 0 {
		t.Fatal("the test reply grants nothing to begin with")
	}
	go c.finishAsync(op, reply)
	cli.SetReadDeadline(time.Now().Add(time.Second))
	got, err := readFrame(cli)
	if err != nil {
		t.Fatal(err)
	}
	if n := binary.LittleEndian.Uint16(got[offCredits:]); n != 0 {
		t.Errorf("the final answer grants %d credits", n)
	}
	if c.seq.limit != before {
		t.Errorf("the window grew by %d for an answer that grants nothing", c.seq.limit-before)
	}
}
