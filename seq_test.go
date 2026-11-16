package smb

import (
	"encoding/binary"
	"testing"
)

// The command sequence window, [MS-SMB2] 3.3.1.1 and 3.3.5.2.3.

func TestSequenceWindowRules(t *testing.T) {
	w := newSeqWindow()
	// A new connection allows exactly { 0 }.
	if w.take(1, 1) {
		t.Error("id 1 was allowed before any credit was granted")
	}
	if !w.take(0, 1) {
		t.Fatal("id 0 refused")
	}
	// "After a sequence number is received, its value MUST never be allowed to be
	// received again."
	if w.take(0, 1) {
		t.Error("id 0 was accepted twice")
	}
	// Credits extend the window: { 0 } and 3 granted is { 0, 1, 2, 3 }.
	w.grant(3)
	if w.take(4, 1) {
		t.Error("id 4 is outside { 0..3 }")
	}
	// Out of order is allowed.
	if !w.take(2, 1) || !w.take(1, 1) || !w.take(3, 1) {
		t.Error("ids 2, 1, 3 refused in that order")
	}
	for _, id := range []uint64{1, 2, 3} {
		if w.take(id, 1) {
			t.Errorf("id %d accepted twice", id)
		}
	}
	if w.base != 4 || len(w.used) != 0 {
		t.Errorf("the window did not close up behind what was used: base %d, %d remembered", w.base, len(w.used))
	}

	// A multi-credit request uses CreditCharge consecutive ids, all of which must
	// be available, and a request that is refused uses up nothing.
	w.grant(8) // limit 12: ids 4..11
	if w.take(10, 4) {
		t.Error("a range running past the window was accepted")
	}
	if !w.take(6, 1) {
		t.Fatal("id 6 refused")
	}
	if w.take(4, 4) { // 4,5,6,7 and 6 is used
		t.Error("a range that overlaps a used id was accepted")
	}
	if !w.take(4, 2) || !w.take(7, 5) {
		t.Error("the free ids of the window were not all available after a refused request")
	}
	// A zero charge is one id.
	w.grant(1)
	if !w.take(12, 0) || w.take(12, 0) {
		t.Error("CreditCharge 0 is not one id")
	}
}

func TestSequenceWindowBounds(t *testing.T) {
	w := newSeqWindow()
	// A range that wraps the 64-bit sequence is refused, not accepted modulo 2^64.
	if w.take(^uint64(0), 2) || w.take(^uint64(0)-1, 3) {
		t.Error("a wrapping range was accepted")
	}
	// The window stops growing rather than wrapping.
	w.limit = ^uint64(0) - 1
	w.grant(10)
	if w.limit != ^uint64(0)-1 {
		t.Errorf("limit wrapped to %d", w.limit)
	}
	// What is remembered ahead of the oldest unused id is bounded: a peer that
	// scatters ids across a huge window is refused, not remembered.
	w = newSeqWindow()
	w.limit = 1 << 40
	for i := uint64(1); i <= maxUsedAhead; i++ {
		if !w.take(i, 1) {
			t.Fatalf("id %d refused below the bound", i)
		}
	}
	if w.take(maxUsedAhead+1, 1) {
		t.Error("the set of remembered ids grew past its bound")
	}
}

func TestGrantedByAddsUpACompound(t *testing.T) {
	mk := func(credits uint16, next uint32) []byte {
		b := make([]byte, headerLen+8)
		binary.LittleEndian.PutUint16(b[offCredits:], credits)
		binary.LittleEndian.PutUint32(b[offNextCommand:], next)
		return b
	}
	chain := append(mk(5, headerLen+8), mk(7, 0)...)
	if got := grantedBy(chain); got != 12 {
		t.Errorf("a compound grants %d, want 12", got)
	}
	// A next-command that points nowhere ends the walk instead of running off.
	if got := grantedBy(mk(3, 0x7fffffff)); got != 3 {
		t.Errorf("a lying NextCommand: %d", got)
	}
	if grantedBy(nil) != 0 || grantedBy([]byte{1, 2}) != 0 {
		t.Error("something that is not a message grants credits")
	}
}

// The window through the dispatcher, the way serve() runs it.
func windowConn(t *testing.T) *conn {
	t.Helper()
	c := newConn(New(), nil)
	c.seq = newSeqWindow()
	return c
}

func echoWithID(id uint64, charge uint16) []byte {
	m := append(requestOf(cmdEcho, []byte{4, 0, 0, 0}), 0, 0, 0, 0)
	binary.LittleEndian.PutUint64(m[offMessageID:], id)
	binary.LittleEndian.PutUint16(m[offCreditCharge:], charge)
	binary.LittleEndian.PutUint16(m[offCredits:], 4) // asks for 4
	return m
}

// A captured request, sent again, ends the connection; a reply grants the credits
// it carries and the window grows by exactly that.
func TestAReplayedRequestEndsTheConnection(t *testing.T) {
	c := windowConn(t)
	first := echoWithID(0, 1)
	reply, err := c.dispatchChain(first)
	if err != nil || statusOf(t, reply) != statusSuccess {
		t.Fatalf("the first request: %v", err)
	}
	if got := binary.LittleEndian.Uint16(reply[offCredits:]); got != 4 {
		t.Fatalf("granted %d, the test expects 4", got)
	}
	if c.seq.limit != 1+4 {
		t.Errorf("the window ends at %d after granting 4, want 5", c.seq.limit)
	}
	// The replay.
	if out, err := c.dispatchChain(first); err == nil {
		t.Errorf("a replayed request was answered (%d bytes)", len(out))
	}
	// An id nobody granted.
	if _, err := c.dispatchChain(echoWithID(9, 1)); err == nil {
		t.Error("an id outside the window was answered")
	}
	// A range that starts inside the window and runs out of it.
	if _, err := c.dispatchChain(echoWithID(4, 3)); err == nil {
		t.Error("a CreditCharge range running past the window was answered")
	}
	// And the honest next request still works.
	if out, err := c.dispatchChain(echoWithID(1, 1)); err != nil || statusOf(t, out) != statusSuccess {
		t.Errorf("an honest request after the refusals: %v", err)
	}
}

// Each operation of a compound has an id of its own, and CANCEL has none.
func TestCompoundAndCancelAgainstTheWindow(t *testing.T) {
	c := windowConn(t)
	c.dispatchChain(echoWithID(0, 1))
	first := echoWithID(1, 1)
	binary.LittleEndian.PutUint32(first[offNextCommand:], uint32(len(first)))
	second := echoWithID(2, 1)
	if _, err := c.dispatchChain(append(first, second...)); err != nil {
		t.Fatalf("a compound of ids 1 and 2: %v", err)
	}
	if _, err := c.dispatchChain(echoWithID(2, 1)); err == nil {
		t.Error("the second operation's id was reusable after the compound")
	}
	// CANCEL consumes nothing and is never refused for its id, whatever it says.
	cancel := requestOf(cmdCancel, []byte{4, 0, 0, 0})
	binary.LittleEndian.PutUint64(cancel[offMessageID:], 0) // an id already used
	before := c.seq.limit
	for i := 0; i < 3; i++ {
		if _, err := c.dispatchChain(cancel); err != nil {
			t.Fatalf("CANCEL refused: %v", err)
		}
	}
	if c.seq.base != 3 || c.seq.limit != before {
		t.Errorf("CANCEL moved the window: base %d limit %d", c.seq.base, c.seq.limit)
	}
}

// The SMB1 greeting uses up id 0 (3.3.5.2.3), and the wildcard answer grants its
// credit, so the SMB2 NEGOTIATE that follows has id 1.
func TestTheLegacyGreetingUsesUpIdZero(t *testing.T) {
	c := windowConn(t)
	greeting := append(smb1ProtocolID[:], 0x72, 0, 0, 0)
	if out, err := c.dispatchChain(greeting); err != nil || len(out) < headerLen {
		t.Fatalf("the greeting: %v", err)
	}
	req := negotiateRequest(dialect302)
	binary.LittleEndian.PutUint64(req[offMessageID:], 1)
	if out, err := c.dispatchChain(req); err != nil || statusOf(t, out) != statusSuccess {
		t.Fatalf("the NEGOTIATE with id 1: %v", err)
	}
	// A second greeting, replayed, is refused like any other replayed id 0.
	if _, err := c.dispatchChain(greeting); err == nil {
		t.Error("the greeting was accepted twice")
	}
}

// With no window (the tests that drive the dispatcher by hand) nothing is refused.
func TestNoWindowRefusesNothing(t *testing.T) {
	c := newConn(New(), nil)
	for i := 0; i < 3; i++ {
		if _, err := c.dispatchChain(echoWithID(0, 1)); err != nil {
			t.Fatal(err)
		}
	}
}
