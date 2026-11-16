// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

var errValidateOn311 = errors.New("smb: FSCTL_VALIDATE_NEGOTIATE_INFO on a 3.1.1 connection")

// errValidateMismatch ends a connection whose client remembers a different
// NEGOTIATE than the one this server answered: a man in the middle, or a bug
// worth the same refusal.
var errValidateMismatch = errors.New("smb: FSCTL_VALIDATE_NEGOTIATE_INFO does not match the negotiate")

// The control codes this server answers. Everything else is refused by name.
const (
	fsctlValidateNegotiateInfo uint32 = 0x00140204
	fsctlDfsGetReferrals       uint32 = 0x00060194
	fsctlPipeTransceive        uint32 = 0x0011C017
)

// ioctl answers the one control code a 3.x client insists on.
//
// FSCTL_VALIDATE_NEGOTIATE_INFO exists because the dialect exchange happens
// BEFORE there is a session, so nothing signs it and a man in the middle could
// have talked both sides down to a weaker dialect. Once the session exists, the
// client asks the server to repeat what it said -- signed this time -- and
// compares. Windows treats a failure as an attack and drops the connection, so
// "not implemented" is not a safe answer for it the way it is for the rest.
//
// The answer must be what was actually negotiated, which is why the server's
// GUID is fixed for its lifetime and the client's own numbers are remembered.
func (c *conn) ioctl(h header, body []byte, msg []byte) ([]byte, error) {
	if len(body) < 56 {
		return nil, fmt.Errorf("smb: IOCTL body of %d bytes is too short", len(body))
	}
	code := binary.LittleEndian.Uint32(body[4:])
	inOff := int(binary.LittleEndian.Uint32(body[24:]))
	inLen := int(binary.LittleEndian.Uint32(body[28:]))
	switch code {
	case fsctlValidateNegotiateInfo:
		// [MS-SMB2] 3.3.5.15.12: on 3.1.1 the pre-authentication hash has
		// already done this job, and a client that asks anyway is not following
		// the dialect it negotiated: the connection is terminated.
		if c.dialect == dialect311 {
			return nil, errValidateOn311
		}
		if inOff < 0 || inLen < 24 || inOff+inLen > len(msg) {
			return errorResponse(h, statusInvalidParameter), nil
		}
		in := msg[inOff : inOff+inLen]
		dialects := int(binary.LittleEndian.Uint16(in[22:]))
		if 24+2*dialects > len(in) {
			return errorResponse(h, statusInvalidParameter), nil
		}
		// [MS-SMB2] 3.3.5.15.12: the response must fit in what the client will
		// accept, and anything the client remembers differently from what this
		// connection negotiated -- the dialects it offered, its GUID, its security
		// mode, its capabilities, or the dialect the server would pick from the list
		// it remembers -- means the exchange was tampered with: the connection is
		// terminated, with no answer for the tamperer to relay.
		if int(binary.LittleEndian.Uint32(body[44:])) < 24 {
			return nil, errValidateMismatch
		}
		theirDialects := readU16s(in[24:], dialects)
		if !slices.Equal(theirDialects, c.clientDialects) || chooseDialect(theirDialects) != c.dialect {
			return nil, errValidateMismatch
		}
		if [16]byte(in[4:20]) != c.clientGuid ||
			binary.LittleEndian.Uint16(in[20:]) != c.clientSecurityMode ||
			binary.LittleEndian.Uint32(in[0:]) != c.clientCapabilities {
			return nil, errValidateMismatch
		}
		out := make([]byte, 24)
		binary.LittleEndian.PutUint32(out[0:], c.serverCaps(c.dialect)) // as NEGOTIATE said
		copy(out[4:], c.srv.guid[:])
		binary.LittleEndian.PutUint16(out[20:], c.serverSecurityMode())
		binary.LittleEndian.PutUint16(out[22:], c.dialect)
		return ioctlResponse(h, code, out, [16]byte{}, statusSuccess), nil

	case fsctlPipeTransceive:
		// Write and read in one round trip, which is how a remote procedure
		// call is made over a pipe: the call goes in the input, the reply
		// comes back in the output. It is the only way `smbutil view` and the
		// Finder ask what shares there are.
		of := c.fileByID(body[8:])
		if of == nil || of.pipe == nil {
			return errorResponse(h, statusFileClosed), nil
		}
		if inOff < 0 || inLen < 0 || inOff+inLen > len(msg) {
			return errorResponse(h, statusInvalidParameter), nil
		}
		reply := of.pipe.answer(c.srv, c.session(h).user, msg[inOff:inOff+inLen])
		if reply == nil {
			// Not something this pipe speaks. INVALID_PARAMETER rather than a
			// fault: a fault is an answer within DCE/RPC, and this was not
			// DCE/RPC at all.
			return errorResponse(h, statusInvalidParameter), nil
		}
		of.pipe.out = reply
		out, more := of.pipe.take(int(binary.LittleEndian.Uint32(body[44:])))
		status := statusSuccess
		if more {
			// As much as fits, and a warning that says so. The client READs
			// the tail from the pipe, which is why it stays on the handle.
			status = statusBufferOverflow
		}
		return ioctlResponse(h, code, out, of.id, status), nil

	case fsctlSrvRequestResumeKey:
		of := c.fileByID(body[8:])
		if of == nil {
			return errorResponse(h, statusFileClosed), nil
		}
		return c.resumeKey(h, of), nil

	case fsctlSrvCopyChunk, fsctlSrvCopyChunkWrite:
		of := c.fileByID(body[8:])
		if of == nil {
			return errorResponse(h, statusFileClosed), nil
		}
		if inOff < 0 || inLen < 0 || inOff+inLen > len(msg) {
			return errorResponse(h, statusInvalidParameter), nil
		}
		return c.copyChunk(h, code, of, msg[inOff:inOff+inLen]), nil

	case fsctlDfsGetReferrals:
		// There is no distributed filesystem here, and saying so is what stops
		// a client looking for one.
		return errorResponse(h, statusNotSupported), nil

	default:
		return errorResponse(h, statusNotSupported), nil
	}
}

func ioctlResponse(h header, code uint32, out []byte, id [16]byte, status uint32) []byte {
	const bodyLen = 48
	b := append(responseTo(h, status), make([]byte, bodyLen+len(out))...)
	rb := b[headerLen:]
	binary.LittleEndian.PutUint16(rb[0:], 49)
	binary.LittleEndian.PutUint32(rb[4:], code)
	// The file id is all zeros for a control code about the CONNECTION -- and
	// the handle's own for one about something opened on it, which a client
	// matches against what it sent.
	copy(rb[8:], id[:])
	//
	// OUTPUT at 32 and 36, not 24 and 28 -- those are the INPUT offset and
	// count, and a response that puts the payload's size there leaves the
	// output count zero. The Linux kernel reads exactly that field and says
	// "Invalid protocol negotiate response size: 0", then refuses the mount.
	binary.LittleEndian.PutUint32(rb[32:], headerLen+bodyLen)
	binary.LittleEndian.PutUint32(rb[36:], uint32(len(out)))
	copy(rb[bodyLen:], out)
	return b
}
