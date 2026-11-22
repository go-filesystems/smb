// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package smb

import "encoding/binary"

// capLargeMTU is SMB2_GLOBAL_CAP_LARGE_MTU (MS-SMB2 2.2.4): "the server
// supports multi-credit operations". Without it a client holds every READ
// and WRITE to 64 KiB whatever MaxReadSize says -- go-smb2 and the Linux
// kernel client both do -- and a megabyte costs sixteen round trips.
const capLargeMTU uint32 = 0x00000004

// capabilitiesFor is what the server claims for a dialect, in the NEGOTIATE
// response and again in VALIDATE_NEGOTIATE_INFO, which the client compares
// with the first and disconnects over if they differ. Multi-credit does not
// exist in 2.0.2, nor in the wildcard answer to the legacy greeting.
func capabilitiesFor(dialect uint16) uint32 {
	if dialect >= dialect210 && dialect != dialectWildcard {
		return capLargeMTU
	}
	return 0
}

// creditsNeeded is MS-SMB2 3.1.5.2's formula: one credit per 64 KiB of the
// larger of what the request sends and the most its response may carry.
//
// It is a uint32 on purpose. A size near 4 GiB needs 65536 credits, which
// is 0 as a uint16: a request asking for that much while paying one credit
// passed the check below, until v0.6.1.
func creditsNeeded(size uint32) uint32 {
	if size == 0 {
		return 1
	}
	return (size-1)/65536 + 1
}

// fixedPart is how many bytes of a request body precede its variable-length
// buffer (MS-SMB2 2.2.x; the StructureSize of each counts the first byte of
// the buffer, the layout does not). The payload of 3.1.5.2 is "the size of the
// data within the variable-length field", so these bytes are not part of it:
// counting them made a WRITE of exactly 64 KiB cost two credits (issue #70).
// A command not listed has no table entry and is measured by its whole body.
var fixedPart = map[command]int{
	cmdCreate:         56,
	cmdWrite:          48,
	cmdSetInfo:        32,
	cmdIoctl:          56,
	cmdQueryDirectory: 32,
	cmdQueryInfo:      40,
}

// payloadSize is max(SendPayloadSize, ExpectedResponsePayloadSize) for one
// request (3.1.5.2): what the request sends in its buffer, and the most its
// response may carry.
//
// What is sent is measured twice and the larger kept: by the buffer actually
// present after the fixed part, and by the length the request declares for
// it, so a request cannot pay for less than it sends by declaring less, nor
// for less than it declares by sending less. A body too short for a field
// read here reads it as 0; the command refuses it on its own terms.
func payloadSize(cmd command, body []byte) uint32 {
	at := func(off int) uint32 {
		if len(body) < off+4 {
			return 0
		}
		return binary.LittleEndian.Uint32(body[off:])
	}
	size := uint32(len(body))
	if fixed, ok := fixedPart[cmd]; ok {
		size = uint32(max(len(body)-fixed, 0))
	}
	switch cmd {
	case cmdRead:
		size = max(size, at(4)) // Length: the response's data
	case cmdWrite, cmdSetInfo:
		size = max(size, at(4)) // Length, BufferLength: the data sent
	case cmdQueryDirectory:
		size = max(size, at(28)) // OutputBufferLength
	case cmdQueryInfo:
		size = max(size, at(4), at(12)) // OutputBufferLength, InputBufferLength
	case cmdChangeNotify:
		size = max(size, at(4)) // OutputBufferLength
	case cmdIoctl:
		// InputCount, MaxInputResponse, MaxOutputResponse
		size = max(size, at(28), at(32), at(44))
	}
	return size
}

// creditChargeTooLow applies MS-SMB2 3.3.5.2.5 to one request on a
// connection that supports multi-credit operations: a request whose
// CreditCharge does not pay for its payload, or for the largest response it
// asks for, is failed with STATUS_INVALID_PARAMETER. Without the check, a
// client could spend one credit on a megabyte, and the credit window that
// bounds what one connection may have in flight would bound nothing.
//
// body is the request after its header; a body too short for the field read
// here is left to the command, which refuses it on its own terms.
func creditChargeTooLow(h header, body []byte) bool {
	size := payloadSize(h.command, body)
	if h.creditCharge == 0 {
		return size > 65536
	}
	return creditsNeeded(size) > uint32(h.creditCharge)
}
