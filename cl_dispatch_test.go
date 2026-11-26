package smb

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// dispatch is where a hostile server meets the client: every rule it checks
// is exercised here with a frame built to break exactly that rule.

type dispCase struct {
	c *ClientConn
	p *clPending
}

func newDisp(t *testing.T, wantEnc, verify bool) dispCase {
	t.Helper()
	c := &ClientConn{pending: map[uint64]*clPending{}, credits: 1, sid: 7, sigAlg: sigCMAC, signKey: make([]byte, 16), ready: true}
	c.cond = sync.NewCond(&c.mu)
	p := &clPending{cmd: cmdCreate, ch: make(chan clResult, 1), verify: verify, wantEnc: wantEnc}
	c.pending[5] = p
	if wantEnc {
		key := make([]byte, 16)
		key[0] = 1
		a, err := newCipherAEAD(cipherAES128GCM, key)
		if err != nil {
			t.Fatal(err)
		}
		c.enc, c.dec, c.encrypted = a, a, true
	}
	return dispCase{c, p}
}

func respMsg(cmd command, id uint64, status uint32, flags uint32, next uint32, credits uint16) []byte {
	m := make([]byte, headerLen+8)
	copy(m, protocolID[:])
	binary.LittleEndian.PutUint16(m[offStructSize:], headerLen)
	binary.LittleEndian.PutUint32(m[offStatus:], status)
	binary.LittleEndian.PutUint16(m[offCommand:], uint16(cmd))
	binary.LittleEndian.PutUint16(m[offCredits:], credits)
	binary.LittleEndian.PutUint32(m[offFlags:], flags)
	binary.LittleEndian.PutUint32(m[offNextCommand:], next)
	binary.LittleEndian.PutUint64(m[offMessageID:], id)
	binary.LittleEndian.PutUint64(m[offSessionID:], 7)
	return m
}

func (d dispCase) delivered() bool {
	select {
	case <-d.p.ch:
		return true
	default:
		return false
	}
}

func TestDispatchAcceptsAGoodResponseAndGrantsCredits(t *testing.T) {
	d := newDisp(t, false, false)
	if err := d.c.dispatch(respMsg(cmdCreate, 5, 0, flagServerToRedir, 0, 9)); err != nil {
		t.Fatal(err)
	}
	if !d.delivered() || d.c.credits != 10 || len(d.c.pending) != 0 {
		t.Fatalf("delivered=%v credits=%d pending=%d", d.delivered(), d.c.credits, len(d.c.pending))
	}
}

func TestDispatchCapsTheCreditsAServerCanGrant(t *testing.T) {
	d := newDisp(t, false, false)
	d.c.credits = clCreditsMax - 1
	if err := d.c.dispatch(respMsg(cmdCreate, 5, 0, flagServerToRedir, 0, 100)); err != nil {
		t.Fatal(err)
	}
	if d.c.credits != clCreditsMax {
		t.Fatalf("credits %d", d.c.credits)
	}
}

func TestDispatchRefusesWhatBreaksTheRules(t *testing.T) {
	for name, tc := range map[string]struct {
		m    []byte
		want string
	}{
		"not a response":    {respMsg(cmdCreate, 5, 0, 0, 0, 1), "not a response"},
		"compounded":        {respMsg(cmdCreate, 5, 0, flagServerToRedir, 128, 1), "compounded"},
		"wrong command":     {respMsg(cmdRead, 5, 0, flagServerToRedir, 0, 1), "answered with"},
		"short":             {respMsg(cmdCreate, 5, 0, flagServerToRedir, 0, 1)[:40], "shorter than a header"},
		"unsigned response": {respMsg(cmdCreate, 5, 0, flagServerToRedir, 0, 1), "signature"},
	} {
		d := newDisp(t, false, name == "unsigned response")
		if err := d.c.dispatch(tc.m); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
		if d.delivered() {
			t.Errorf("%s: delivered", name)
		}
	}
}

func TestDispatchIgnoresWhatAnswersNothing(t *testing.T) {
	d := newDisp(t, false, false)
	if err := d.c.dispatch(respMsg(cmdCreate, 99, 0, flagServerToRedir, 0, 1)); err != nil {
		t.Fatalf("an answer to nothing: %v", err)
	}
	before := d.c.credits
	if err := d.c.dispatch(respMsg(cmdOplockBreak, ^uint64(0), 0, flagServerToRedir, 0, 40)); err != nil {
		t.Fatalf("an unsolicited break: %v", err)
	}
	if d.c.credits != before {
		t.Fatalf("an unsolicited break granted credits: %d", d.c.credits)
	}
	if d.delivered() || len(d.c.pending) != 1 {
		t.Fatal("the pending request was disturbed")
	}
	// an oplock break with a real id is a command mismatch, not a break
	if err := d.c.dispatch(respMsg(cmdOplockBreak, 5, 0, flagServerToRedir, 0, 1)); err == nil {
		t.Fatal("an OPLOCK_BREAK answered a CREATE")
	}
}

func TestDispatchBoundsInterimResponses(t *testing.T) {
	d := newDisp(t, false, false)
	interim := respMsg(cmdCreate, 5, statusPending, flagServerToRedir|flagAsyncCommand, 0, 3)
	d.p.interim = clMaxInterim - 2
	for i := 0; i < 2; i++ {
		if err := d.c.dispatch(interim); err != nil {
			t.Fatalf("interim %d: %v", i, err)
		}
	}
	if d.delivered() || d.c.credits != 7 {
		t.Fatalf("delivered=%v credits=%d", d.delivered(), d.c.credits)
	}
	if err := d.c.dispatch(interim); err == nil {
		t.Fatal("STATUS_PENDING without end was accepted")
	}
	// the same status without the async flag is the final answer
	d = newDisp(t, false, false)
	if err := d.c.dispatch(respMsg(cmdCreate, 5, statusPending, flagServerToRedir, 0, 1)); err != nil || !d.delivered() {
		t.Fatalf("sync pending: %v", err)
	}
}

func TestDispatchSignatures(t *testing.T) {
	good := respMsg(cmdCreate, 5, 0, flagServerToRedir|flagSigned, 0, 1)
	signMessage(sigCMAC, make([]byte, 16), good)
	d := newDisp(t, false, true)
	if err := d.c.dispatch(good); err != nil || !d.delivered() {
		t.Fatalf("good signature: %v", err)
	}
	bad := append([]byte(nil), good...)
	bad[offSignature] ^= 1
	d = newDisp(t, false, true)
	if err := d.c.dispatch(bad); err == nil || d.delivered() {
		t.Fatal("a wrong signature was accepted")
	}
	flagless := respMsg(cmdCreate, 5, 0, flagServerToRedir, 0, 1)
	copy(flagless[offSignature:], good[offSignature:offSignature+16])
	d = newDisp(t, false, true)
	if err := d.c.dispatch(flagless); err == nil {
		t.Fatal("a response without the signed flag was accepted")
	}
}

func (d dispCase) sealed(m []byte) []byte { return d.c.seal(d.c.enc, d.c.sid, m)[4:] }

func TestDispatchEncryption(t *testing.T) {
	defer recovered(t)
	m := respMsg(cmdCreate, 5, 0, flagServerToRedir, 0, 1)
	d := newDisp(t, true, false)
	if err := d.c.dispatch(d.sealed(m)); err != nil || !d.delivered() {
		t.Fatalf("good encrypted response: %v", err)
	}
	// a plaintext answer to an encrypted request is a downgrade
	d = newDisp(t, true, false)
	if err := d.c.dispatch(m); err == nil || d.delivered() || !strings.Contains(err.Error(), "protection differs") {
		t.Fatalf("plaintext where encryption was in force: %v", err)
	}
	// an encrypted answer to a request that was signed
	e := newDisp(t, true, false)
	f := e.sealed(m)
	d = newDisp(t, false, true)
	d.c.dec = e.c.dec
	if err := d.c.dispatch(f); err == nil || !strings.Contains(err.Error(), "protection differs") {
		t.Fatalf("encrypted answer for an unencrypted request: %v", err)
	}
	for name, mut := range map[string]func(f []byte) []byte{
		"tag":         func(f []byte) []byte { f[offTrSignature] ^= 1; return f },
		"ciphertext":  func(f []byte) []byte { f[transformLen] ^= 1; return f },
		"nonce":       func(f []byte) []byte { f[offTrNonce] ^= 1; return f },
		"session":     func(f []byte) []byte { f[offTrSessionID] ^= 1; return f },
		"flags":       func(f []byte) []byte { f[offTrFlags] = 0; return f },
		"orig size":   func(f []byte) []byte { f[offTrOrigSize]++; return f },
		"header only": func(f []byte) []byte { return f[:transformLen] },
	} {
		d = newDisp(t, true, false)
		if err := d.c.dispatch(mut(d.sealed(m))); !errors.Is(err, errTransform) || d.delivered() {
			t.Errorf("%s: %v", name, err)
		}
	}
	// no key: a transform header cannot be read at all
	d = newDisp(t, true, false)
	fr := d.sealed(m)
	d.c.dec = nil
	if err := d.c.dispatch(fr); !errors.Is(err, errTransform) {
		t.Fatalf("encrypted frame with no decryption key: %v", err)
	}
}

func TestRoundTripHonoursACancelledContext(t *testing.T) {
	defer recovered(t)
	d := newDisp(t, false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	a, b := net.Pipe() // a connection that is shut: anything that gets as far as sending fails with another error
	a.Close()
	b.Close()
	d.c.nc = a
	d.c.credits = 0 // no credit to send with: it must wait, then give up
	if _, err := d.c.roundTrip(ctx, cmdEcho, 0, 1, clEmptyRequest(), nil, false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting for credit: %v", err)
	}
	if len(d.c.pending) != 1 {
		t.Fatalf("pending %d", len(d.c.pending))
	}
	d.c.err = context.Canceled
	if _, err := d.c.roundTrip(context.Background(), cmdEcho, 0, 1, clEmptyRequest(), nil, false); err != context.Canceled {
		t.Fatalf("on a dead connection: %v", err)
	}
}

func TestCreditChargeRoundsUp(t *testing.T) {
	for n, want := range map[int]uint16{0: 1, 1: 1, clChunk: 1, clChunk + 1: 2, 3 * clChunk: 3, 3*clChunk + 1: 4} {
		if got := creditCharge(n); got != want {
			t.Errorf("creditCharge(%d) = %d, want %d", n, got, want)
		}
	}
}
