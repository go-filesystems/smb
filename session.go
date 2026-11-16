// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"encoding/binary"
	"fmt"
	"log/slog"
)

// sessionSetup runs the two halves of NTLM.
//
// The client sends its first message and gets STATUS_MORE_PROCESSING_REQUIRED
// with a challenge; it answers, and gets success or a logon failure. The
// session id is allocated on the FIRST half, because the client puts it in the
// header of the second -- a server that waits until the user is known has
// nothing to match the answer against.
//
// On 3.1.1 the exchange is also folded into the pre-authentication integrity
// hash ([MS-SMB2] 3.3.5.5.3): both requests and the first response, but not the
// last response, which is signed with the key the hash produces.
func (c *conn) sessionSetup(h header, body, msg []byte) ([]byte, error) {
	if len(body) < 24 {
		return nil, fmt.Errorf("smb: SESSION_SETUP body of %d bytes is too short", len(body))
	}
	secOff := int(binary.LittleEndian.Uint16(body[12:]))
	secLen := int(binary.LittleEndian.Uint16(body[14:]))
	// The offset is from the start of the message, not of the body.
	secOff -= headerLen
	if secOff < 0 || secLen < 0 || secOff+secLen > len(body) {
		return nil, fmt.Errorf("smb: the security buffer is not inside the message")
	}
	token, wrapped, err := mechTokenOf(body[secOff : secOff+secLen])
	if err != nil {
		return errorResponse(h, statusLogonFailure), nil
	}
	if len(token) < 12 {
		return errorResponse(h, statusLogonFailure), nil
	}

	switch binary.LittleEndian.Uint32(token[8:]) {
	case ntlmNegotiate:
		ch, challenge, err := newChallenge(c.srv.serverName())
		if err != nil {
			return nil, err
		}
		c.pending = ch
		c.spnego = wrapped
		if c.dialect == dialect311 {
			c.pendingPreauth = preauthExtend(c.preauth, msg)
		}
		id := h.sessionID
		if id == 0 {
			c.nextID++
			id = c.nextID
		}
		h.sessionID = id
		// In kind: wrapped for a client that wrapped, bare for one that did
		// not. Linux's kernel client is the second kind.
		reply := challenge
		if wrapped {
			reply = negTokenRespChallenge(challenge)
		}
		resp := c.sessionSetupResponse(h, statusMoreProcessing, reply)
		if c.dialect == dialect311 {
			c.pendingPreauth = preauthExtend(c.pendingPreauth, resp)
		}
		return resp, nil

	case ntlmAuth:
		if c.pending == nil {
			return errorResponse(h, statusLogonFailure), nil
		}
		auth, err := parseAuth(token)
		if err != nil {
			return errorResponse(h, statusLogonFailure), nil
		}
		cred, known := c.srv.credentialFor(auth.user)
		if !known {
			// The same status for an unknown user as for a wrong password: a
			// server that distinguishes them tells a stranger which names
			// exist.
			return errorResponse(h, statusLogonFailure), nil
		}
		key, ok := c.pending.verify(auth, cred)
		if !ok {
			return errorResponse(h, statusLogonFailure), nil
		}
		c.pending = nil
		var preauth []byte
		if c.dialect == dialect311 {
			// The last request is in the hash that derives the keys; the last
			// response, which they sign, is not.
			preauth = preauthExtend(c.pendingPreauth, msg)
			c.pendingPreauth = nil
		}
		c.sessions[h.sessionID] = &session{
			user:       auth.user,
			sessionKey: key,
			signingKey: signingKeyFor(c.dialect, key, preauth),
		}
		c.logSession(h.sessionID, auth.user)
		var done []byte
		if c.spnego {
			done = negTokenRespAccept()
		}
		// The last message of the authentication is signed even though the
		// request was not: it is the first thing a client can check, and it
		// is what proves the server holds the same key.
		reply := c.sessionSetupResponse(h, statusSuccess, done)
		signMessage(c.signAlgo(), c.sessions[h.sessionID].signingKey, reply)
		return reply, nil

	default:
		return errorResponse(h, statusLogonFailure), nil
	}
}

// logSession says, on the server's Logger at Debug level, what an
// authenticated session negotiated: the dialect and the signing algorithm. It is
// how a deployment reads what a given client actually got.
func (c *conn) logSession(id uint64, user string) {
	l := slog.Default()
	if c.srv != nil && c.srv.Logger != nil {
		l = c.srv.Logger
	}
	l.Debug("smb session established", "session", id, "user", user,
		"dialect", dialectName(c.dialect), "signing", c.signAlgo().String())
}

// dialectName is "3.1.1" for 0x0311.
func dialectName(d uint16) string {
	switch d {
	case dialect202:
		return "2.0.2"
	case dialect210:
		return "2.1"
	case dialect300:
		return "3.0"
	case dialect302:
		return "3.0.2"
	case dialect311:
		return "3.1.1"
	}
	return fmt.Sprintf("%#04x", d)
}

func (a sigAlgo) String() string {
	switch a {
	case sigGMAC:
		return "AES-128-GMAC"
	case sigCMAC:
		return "AES-128-CMAC"
	}
	return "HMAC-SHA256"
}

// sessionSetupResponse builds the 8-byte body plus its security buffer.
func (c *conn) sessionSetupResponse(h header, status uint32, sec []byte) []byte {
	const bodyLen = 8 // structure size says 9 for "and a buffer"
	b := append(responseTo(h, status), make([]byte, bodyLen+len(sec))...)
	body := b[headerLen:]
	binary.LittleEndian.PutUint16(body[0:], 9)
	binary.LittleEndian.PutUint16(body[2:], 0) // session flags: not guest, not null
	binary.LittleEndian.PutUint16(body[4:], headerLen+bodyLen)
	binary.LittleEndian.PutUint16(body[6:], uint16(len(sec)))
	copy(body[bodyLen:], sec)
	return b
}

// session returns the authenticated session a message belongs to.
func (c *conn) session(h header) *session {
	return c.sessions[h.sessionID]
}
