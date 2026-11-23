// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

// The sizes this server advertises. They bound one message, and a client will
// not ask for more than it was told.
const (
	maxTransactSize = 1 << 20
	maxReadSize     = 1 << 20
	maxWriteSize    = 1 << 20
)

// dialectsWeSpeak, in the order a server should prefer.
//
// 3.1.1 adds pre-authentication integrity and negotiate contexts (negctx.go,
// preauth.go); 3.0.2 and 3.0 sign with AES-CMAC and derive their key rather than
// using the session key directly; 2.1 signs with HMAC-SHA256. All four are
// honoured here. Encryption is not: no ENCRYPTION context is answered, so a
// client sees a server that does not offer it.
//
// 2.0.2 exists only for Vista and is left out.
var dialectsWeSpeak = []uint16{dialect311, dialect302, dialect300, dialect210}

// errRenegotiate ends a connection whose client sends a second NEGOTIATE:
// [MS-SMB2] 3.3.5.4, "the server MUST disconnect the connection ... and not
// reply", once a dialect has been chosen.
var errRenegotiate = errors.New("smb: a second NEGOTIATE on one connection")

// legacyNegotiateResponse answers the one SMB1 message this server reads.
//
// A client that has spoken SMB2 before still opens with the 1996 greeting,
// offering "NT LM 0.12", "SMB 2.002" and "SMB 2.???" -- measured, on macOS 26.
// The answer is an SMB2 NEGOTIATE response naming the wildcard dialect 0x02FF,
// which means "send me a real SMB2 negotiate". The contents of the SMB1
// message are never parsed: there is exactly one thing to say back.
func (c *conn) legacyNegotiateResponse() ([]byte, error) {
	return c.negotiateResponse(header{command: cmdNegotiate}, dialectWildcard, nil), nil
}

// negotiate answers an SMB2 NEGOTIATE by choosing a dialect both sides speak.
//
// msg is the whole request, because 3.1.1 hashes it (see preauth.go) and its
// negotiate contexts are addressed from the start of the header.
func (c *conn) negotiate(h header, body, msg []byte) ([]byte, error) {
	if len(body) < 36 {
		return nil, fmt.Errorf("smb: NEGOTIATE body of %d bytes is too short", len(body))
	}
	if c.dialect != 0 {
		return nil, errRenegotiate
	}
	// [MS-SMB2] 3.3.5.2.4: a NEGOTIATE has no session to sign it.
	if h.flags&flagSigned != 0 {
		return errorResponse(h, statusInvalidParameter), nil
	}
	count := int(binary.LittleEndian.Uint16(body[2:]))
	if count == 0 {
		return errorResponse(h, statusInvalidParameter), nil
	}
	offered := make([]uint16, 0, count)
	for i, off := 0, 36; i < count && off+2 <= len(body); i, off = i+1, off+2 {
		offered = append(offered, binary.LittleEndian.Uint16(body[off:]))
	}
	chosen := chooseDialect(offered)
	if chosen == 0 {
		// NOT_SUPPORTED rather than a dialect nobody asked for: a client told
		// "0x0210" when it never offered it has no way to interpret the rest.
		return errorResponse(h, statusNotSupported), nil
	}

	var (
		ctxs     []outContext
		hashID   uint16
		cipherID = cipherNone
		signAlgo = signIDAESCMAC
	)
	if chosen == dialect311 {
		// The contexts start after the dialect array, so an offset inside the
		// fixed part or the array itself is a lie about where they are.
		ctxOff := int(binary.LittleEndian.Uint32(body[28:]))
		ctxCount := int(binary.LittleEndian.Uint16(body[32:]))
		if ctxOff < headerLen+36+2*count {
			return errorResponse(h, statusInvalidParameter), nil
		}
		cc, status := parseNegotiateContexts(msg, ctxOff, ctxCount)
		if status != statusSuccess {
			return errorResponse(h, status), nil
		}
		// [MS-SMB2] 3.3.5.4: a TRANSPORT_CAPABILITIES context shorter than its
		// structure fails the request. It is read on a QUIC connection only.
		if c.transport == "quic" && (cc.shortTrans || cc.transports > 1) {
			return errorResponse(h, statusInvalidParameter), nil
		}
		var ok bool
		if hashID, ok = chooseHash(cc.hashes); !ok {
			return errorResponse(h, statusNoPreauthHashOverlap), nil
		}
		salt := make([]byte, 32)
		rand.Read(salt)
		ctxs = append(ctxs, preauthContext(hashID, salt))
		// [MS-SMB2] 3.3.5.4: an ENCRYPTION context the server supports is
		// ALWAYS answered, with cipher 0 when nothing is shared, so that a client
		// can tell "no common cipher" from "does not encrypt" (no context).
		// "If the underlying connection is over QUIC, DisableEncryptionOverSecureTransport
		// is TRUE and SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY is set, the server MUST set
		// Connection.AcceptTransportSecurity to TRUE", and the response carries the flag.
		if c.transport == "quic" && c.srv.DisableEncryptionOverSecureTransport &&
			cc.transports == 1 && cc.transportFlg&flagAcceptTransportSecurity != 0 {
			c.acceptTransportSecurity = true
			ctxs = append(ctxs, transportContext(flagAcceptTransportSecurity))
		}
		if cc.hasCipher && !c.srv.DisableEncryption && !c.acceptTransportSecurity {
			cipherID = chooseCipher(cc.ciphers)
			ctxs = append(ctxs, cipherContext(cipherID))
		}
		if cc.hasSigning {
			signAlgo = chooseSigning(cc.signing)
			ctxs = append(ctxs, signingContext(signAlgo))
		}
	}

	c.dialect = chosen
	// What VALIDATE_NEGOTIATE_INFO will be compared with ([MS-SMB2] 3.3.5.4:
	// Connection.ClientDialects and Connection.ClientGuid).
	c.clientDialects = offered
	copy(c.clientGuid[:], body[12:28])
	c.clientSecurityMode = binary.LittleEndian.Uint16(body[4:])
	c.clientCapabilities = binary.LittleEndian.Uint32(body[8:])
	c.signingAlgorithm = signAlgo
	c.cipherID = cipherID
	resp := c.negotiateResponse(h, chosen, ctxs)
	if chosen == dialect311 {
		// The chain starts at zero and takes the request and the response as
		// they were on the wire; nothing may touch `resp` after this.
		c.preauth = preauthExtend(preauthExtend(preauthStart(), msg), resp)
	}
	return resp, nil
}

// serverCaps is what the server claims in NEGOTIATE and again in
// VALIDATE_NEGOTIATE_INFO. SMB2_GLOBAL_CAP_ENCRYPTION is claimed on 3.0 and
// 3.0.2 to a client that has it, and on no other dialect: 3.1.1 negotiates a
// cipher in a context instead, and its response table marks the bit as invalid
// ([MS-SMB2] 2.2.4).
func (c *conn) serverCaps(dialect uint16) uint32 {
	caps := capabilitiesFor(dialect)
	if !c.supportsMultiCredit() {
		caps &^= capLargeMTU
	}
	if (dialect == dialect300 || dialect == dialect302) && c.encCapable() {
		caps |= capEncryption
	}
	return caps
}

// serverSecurityMode is what the server says in NEGOTIATE (and repeats in
// VALIDATE_NEGOTIATE_INFO): signing is enabled, and required when
// [Server.RequireSigning] says so ([MS-SMB2] 3.3.5.4).
func (c *conn) serverSecurityMode() uint16 {
	if c.srv.RequireSigning {
		return signingEnabled | signingRequired
	}
	return signingEnabled
}

// chooseDialect is the greatest dialect both sides speak, or 0.
func chooseDialect(offered []uint16) uint16 {
	for _, ours := range dialectsWeSpeak {
		if slices.Contains(offered, ours) {
			return ours
		}
	}
	return 0
}

// negotiateResponse builds the header and body of a NEGOTIATE response. ctxs
// is the NegotiateContextList of a 3.1.1 answer, and nil for any other dialect.
func (c *conn) negotiateResponse(h header, dialect uint16, ctxs []outContext) []byte {
	// The security buffer says which authentication mechanisms exist. Offering
	// exactly one, NTLM, is what makes the client's next message predictable.
	sec := negTokenInit(c.srv.Kerberos != nil, !c.srv.DisableNTLM)

	const bodyLen = 64 // the fixed part; structure size says 65 for "and a buffer"
	b := append(responseTo(h, statusSuccess), make([]byte, bodyLen+len(sec))...)
	body := b[headerLen:]
	binary.LittleEndian.PutUint16(body[0:], 65)
	binary.LittleEndian.PutUint16(body[2:], c.serverSecurityMode())
	binary.LittleEndian.PutUint16(body[4:], dialect)
	binary.LittleEndian.PutUint32(body[24:], c.serverCaps(dialect))
	copy(body[8:24], c.srv.guid[:]) // identity, not a secret -- and stable, because
	//                                 the validate-negotiate exchange below
	//                                 compares it against what was sent here
	tx, rd, wr := uint32(maxTransactSize), uint32(maxReadSize), uint32(maxWriteSize)
	if !c.supportsMultiCredit() {
		// One credit carries 64 KiB, and without multi-credit no request may
		// ask for more ([MS-SMB2] 3.1.5.2), so the sizes are not promised.
		tx, rd, wr = 65536, 65536, 65536
	}
	binary.LittleEndian.PutUint32(body[28:], tx)
	binary.LittleEndian.PutUint32(body[32:], rd)
	binary.LittleEndian.PutUint32(body[36:], wr)
	now := filetime(time.Now())
	binary.LittleEndian.PutUint64(body[40:], now)
	binary.LittleEndian.PutUint64(body[48:], now)
	binary.LittleEndian.PutUint16(body[56:], headerLen+bodyLen)
	binary.LittleEndian.PutUint16(body[58:], uint16(len(sec)))
	copy(body[bodyLen:], sec)
	if len(ctxs) > 0 {
		// NegotiateContextCount at body[6], NegotiateContextOffset at body[60]:
		// the list starts on the next 8-byte boundary after the security buffer.
		for len(b)%8 != 0 {
			b = append(b, 0)
		}
		binary.LittleEndian.PutUint16(b[headerLen+6:], uint16(len(ctxs)))
		binary.LittleEndian.PutUint32(b[headerLen+60:], uint32(len(b)))
		b = appendContexts(b, ctxs)
	}
	return b
}
