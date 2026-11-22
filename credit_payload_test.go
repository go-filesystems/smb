// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// specCharge is MS-SMB2 3.1.5.2 verbatim, written apart from the code under
// test: CreditCharge = (max(SendPayloadSize, ExpectedResponsePayloadSize) - 1)
// / 65536 + 1. The unit is the spec's, named once.
const creditUnit = 65536

func specCharge(payload int) int {
	if payload < 1 {
		return 1
	}
	return (payload-1)/creditUnit + 1
}

// A payload is "the size of the data within the variable-length field"
// (3.1.5.2, 3.3.5.2.5): the fixed structure that precedes it is not part of
// it. Each class below says where its fixed part ends and which field of the
// request, if any, declares the data it sends or the response it allows.
// Fixed sizes are the StructureSize-less layouts of MS-SMB2 2.2.x.
type payloadClass struct {
	name  string
	cmd   command
	fixed int // bytes of the request before its variable buffer
	send  int // offset of the field declaring the data sent, or -1
	resp  int // offset of the field declaring the response size, or -1
	// carries is true when the payload travels in the request's own buffer,
	// after the fixed part.
	carries bool
}

var payloadClasses = []payloadClass{
	{"WRITE", cmdWrite, 48, 4, -1, true},
	{"SET_INFO", cmdSetInfo, 32, 4, -1, true},
	{"IOCTL input", cmdIoctl, 56, 28, -1, true},
	{"IOCTL output", cmdIoctl, 56, -1, 44, false},
	{"READ", cmdRead, 48, -1, 4, false},
	{"QUERY_DIRECTORY", cmdQueryDirectory, 32, -1, 28, false},
	{"QUERY_INFO output", cmdQueryInfo, 40, -1, 4, false},
	{"QUERY_INFO input", cmdQueryInfo, 40, 12, -1, true},
	{"CHANGE_NOTIFY", cmdChangeNotify, 32, -1, 4, false},
}

func (pc payloadClass) request(n int) []byte {
	body := make([]byte, pc.fixed)
	if pc.carries {
		body = append(body, make([]byte, n)...)
	}
	if pc.send >= 0 {
		binary.LittleEndian.PutUint32(body[pc.send:], uint32(n))
	}
	if pc.resp >= 0 {
		binary.LittleEndian.PutUint32(body[pc.resp:], uint32(n))
	}
	return body
}

// The boundary is driven by the spec formula: for every payload size, the
// request is accepted at exactly the credits the formula gives and refused
// one credit below.
func TestCreditChargeFollowsThePayloadNotTheStructure(t *testing.T) {
	var sizes []int
	for _, n := range []int{1, 2, 16, 17} {
		sizes = append(sizes, n*creditUnit-1, n*creditUnit, n*creditUnit+1)
	}
	sizes = append(sizes, 1, creditUnit/2, 2*creditUnit)
	for _, pc := range payloadClasses {
		for _, n := range sizes {
			t.Run(fmt.Sprintf("%s/%d", pc.name, n), func(t *testing.T) {
				body := pc.request(n)
				want := specCharge(n)
				h := header{command: pc.cmd, creditCharge: uint16(want)}
				if creditChargeTooLow(h, body) {
					t.Errorf("payload %d charged %d (the spec's number) was refused", n, want)
				}
				if want > 1 {
					h.creditCharge = uint16(want - 1)
					if !creditChargeTooLow(h, body) {
						t.Errorf("payload %d charged %d, one below the spec's %d, was accepted", n, want-1, want)
					}
				}
				// CreditCharge 0 pays for one credit's worth: the spec fails
				// a request whose payload is larger than that.
				h.creditCharge = 0
				if got, wantRefused := creditChargeTooLow(h, body), n > creditUnit; got != wantRefused {
					t.Errorf("payload %d charged 0: too low = %v, want %v", n, got, wantRefused)
				}
			})
		}
	}
}

// A request cannot pay less than it sends by declaring a smaller field than
// the buffer it carries.
func TestACarriedPayloadIsMeasuredByTheBufferToo(t *testing.T) {
	for _, pc := range payloadClasses {
		if !pc.carries {
			continue
		}
		t.Run(pc.name, func(t *testing.T) {
			n := 3*creditUnit + 1
			body := pc.request(n)
			if pc.send >= 0 {
				binary.LittleEndian.PutUint32(body[pc.send:], 0) // lies: says nothing sent
			}
			h := header{command: pc.cmd, creditCharge: uint16(specCharge(n) - 1)}
			if !creditChargeTooLow(h, body) {
				t.Errorf("%d bytes sent under a declared 0, charged %d, was accepted", n, h.creditCharge)
			}
		})
	}
}

// A field is read only when all four of its bytes are in the body: on either
// side of that edge the answer differs, so the guard is held by an assertion.
func TestAFieldIsReadOnlyWhole(t *testing.T) {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[4:], 2*creditUnit) // READ Length
	h := header{command: cmdRead, creditCharge: 1}
	if !creditChargeTooLow(h, body) {
		t.Error("a READ whose Length is whole in the body, charged 1 for 2 units, was accepted")
	}
	if creditChargeTooLow(h, body[:7]) {
		t.Error("a READ cut inside its Length field was refused on a field it does not hold")
	}
}
