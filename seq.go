// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"encoding/binary"
	"errors"
	"sync"
)

// The command sequence window, [MS-SMB2] 3.3.1.1 and 3.3.5.2.3.
//
// Every request carries a MessageId, and the server keeps the set of ids it is
// willing to receive: { 0 } when the connection begins, growing by the credits it
// grants in each response. An id that is received is removed, and "its value MUST
// never be allowed to be received again". That is what makes a captured request
// worthless to replay: a signature or an authentication tag proves who made a
// message, and the window is what proves it is new.
//
// Out of order is allowed (the window is a set, not a counter), a multi-credit
// request uses CreditCharge consecutive ids, and an id outside the window ends
// the connection (3.3.5.2.3: "SHOULD terminate the connection").
//
// The window is [base, limit) with the ids already used inside it:
//
//	ids below base      all used
//	base ... limit-1    granted; the ones in `used` have been received
//	limit and above     not granted yet

// maxUsedAhead bounds the ids remembered above base. A well-behaved client keeps a
// few hundred requests outstanding; a peer that sends ids scattered across a
// window of millions, each costing the server a set entry, is refused rather than
// remembered.
const maxUsedAhead = 1 << 16

type seqWindow struct {
	mu          sync.Mutex
	base, limit uint64
	used        map[uint64]struct{}
}

func newSeqWindow() *seqWindow {
	return &seqWindow{limit: 1, used: map[uint64]struct{}{}}
}

// take consumes charge consecutive ids starting at id, and says whether they were
// all available. A request that is not taken changes nothing.
func (w *seqWindow) take(id uint64, charge uint32) bool {
	if charge == 0 {
		charge = 1
	}
	end := id + uint64(charge)
	w.mu.Lock()
	defer w.mu.Unlock()
	if end < id || id < w.base || end > w.limit {
		return false
	}
	for i := id; i < end; i++ {
		if _, dup := w.used[i]; dup {
			return false
		}
	}
	if len(w.used)+int(charge) > maxUsedAhead {
		return false
	}
	for i := id; i < end; i++ {
		w.used[i] = struct{}{}
	}
	for {
		if _, ok := w.used[w.base]; !ok {
			break
		}
		delete(w.used, w.base)
		w.base++
	}
	return true
}

// grant extends the window by n ids: the credits a response carries.
func (w *seqWindow) grant(n uint16) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.limit+uint64(n) < w.limit {
		return // the 64-bit sequence would wrap: grant no more
	}
	w.limit += uint64(n)
}

// grantedBy adds up the CreditResponse of every message in a (possibly
// compounded) reply, which is how many ids the client has just been given.
func grantedBy(reply []byte) uint64 {
	var total uint64
	for len(reply) >= headerLen {
		total += uint64(binary.LittleEndian.Uint16(reply[offCredits:]))
		next := int(binary.LittleEndian.Uint32(reply[offNextCommand:]))
		if next < headerLen || next > len(reply) {
			break
		}
		reply = reply[next:]
	}
	return total
}

// noteReply extends the window by the credits a reply is about to give. It runs on
// every message the server sends, before it is sent, and so before the client can
// use what it carries.
func (c *conn) noteReply(plain []byte) {
	if c.seq == nil {
		return
	}
	for n := grantedBy(plain); n > 0; {
		step := uint16(min(n, 0xFFFF))
		c.seq.grant(step)
		n -= uint64(step)
	}
}

// errSequence ends a connection whose client sent a MessageId the window does not
// hold: replayed, never granted, or one of a range its CreditCharge claims.
var errSequence = errors.New("smb: a MessageId outside the command sequence window")
