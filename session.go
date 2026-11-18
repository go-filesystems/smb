// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"slices"
	"time"
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
	// [MS-SMB2] 3.3.5.5 steps 1 and 2, before anything else is read: a server that
	// requires encryption does not let in a client that cannot do it.
	if c.srv.EncryptData && !c.encCapable() {
		return errorResponse(h, statusAccessDenied), nil
	}
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
	krb := isKerberosToken(token)
	if !krb && len(token) < 12 {
		return errorResponse(h, statusLogonFailure), nil
	}

	// [MS-SMB2] 3.3.5.5: a SESSION_SETUP names one of three things. SessionId 0 is
	// a new session, and its id is the SERVER's to choose; a SessionId that is
	// already a session is that session authenticating again; any other id was
	// never given out by this server (or is the exchange this very connection is in
	// the middle of), and a client does not get to choose a fresh one.
	existing := c.sessions[h.sessionID]
	if h.sessionID != 0 && existing == nil && c.exchanges[h.sessionID] == nil {
		return errorResponse(h, statusUserSessionDeleted), nil
	}
	// Authenticating again, as the same session: the session is not replaced, so
	// whoever asks has to prove they are its owner first -- the request must be
	// signed with the session's own key (verified before it gets here) or
	// encrypted, as 3.3.5.5.2 requires, or anybody on the connection who can make
	// up a valid account could take the session over.
	if existing != nil && h.flags&flagSigned == 0 && !h.encrypted {
		return errorResponse(h, statusAccessDenied), nil
	}

	if krb {
		return c.sessionSetupKerberos(h, msg, body[secOff:secOff+secLen], token, wrapped, existing)
	}
	if c.srv.DisableNTLM {
		c.logRefused(h, "NTLMSSP, and the server has NTLM disabled")
		return errorResponse(h, statusLogonFailure), nil
	}

	switch binary.LittleEndian.Uint32(token[8:]) {
	case ntlmNegotiate:
		ch, challenge, err := newChallenge(c.srv.serverName())
		if err != nil {
			return nil, err
		}
		ex := &exchange{challenge: ch, spnego: wrapped, reauth: existing}
		if c.dialect == dialect311 {
			ex.preauth = preauthExtend(c.preauth, msg)
		}
		id := h.sessionID
		if id == 0 {
			// The server's choice, and never an id that is a session or an exchange
			// already.
			for {
				c.nextID++
				if c.nextID != 0 && c.sessions[c.nextID] == nil && c.exchanges[c.nextID] == nil {
					break
				}
			}
			id = c.nextID
		}
		h.sessionID = id
		// Keyed by the id it was given, so another SESSION_SETUP -- an injected one
		// with SessionId 0, say -- starts an exchange of its own and cannot overwrite
		// this one.
		c.beginExchange(id, ex)
		// In kind: wrapped for a client that wrapped, bare for one that did
		// not. Linux's kernel client is the second kind.
		reply := challenge
		if wrapped {
			reply = negTokenRespChallenge(challenge)
		}
		resp := c.sessionSetupResponse(h, statusMoreProcessing, 0, reply)
		if c.dialect == dialect311 {
			ex.preauth = preauthExtend(ex.preauth, resp)
		}
		return resp, nil

	case ntlmAuth:
		// The answer is for the session that was allocated to the challenge: a
		// session id the client makes up (0, say, which means "no session") is not
		// one this exchange created.
		ex := c.exchanges[h.sessionID]
		if ex == nil || h.sessionID == 0 {
			return errorResponse(h, statusLogonFailure), nil
		}
		// An answer is an exchange's last leg, whatever it says: from here, every
		// refusal -- an unparseable token, an unknown user, a wrong password -- has
		// ended it, and a client starts again from the first leg.
		c.endExchange(h.sessionID)
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
		key, ok := ex.challenge.verify(auth, cred)
		if !ok {
			return errorResponse(h, statusLogonFailure), nil
		}
		reauth := ex.reauth
		if reauth != nil {
			// A session authenticating again keeps everything it has -- its keys,
			// its trees, its handles -- and must be the same user: a different one
			// is refused, and the session it asked to take over is left exactly as
			// it was. (The session must also still be the one the exchange began
			// with, and the request signed or encrypted like the first.)
			if existing != reauth || auth.user != reauth.user {
				return errorResponse(h, statusAccessDenied), nil
			}
			var flags uint16
			if reauth.encryptData {
				flags |= sessionFlagEncryptData
			}
			var done []byte
			if ex.spnego {
				done = negTokenRespAccept()
			}
			reply := c.sessionSetupResponse(h, statusSuccess, flags, done)
			signMessage(c.signAlgo(), reauth.signingKey, reply)
			return reply, nil
		}
		var preauth []byte
		if c.dialect == dialect311 {
			// The last request is in the hash that derives the keys; the last
			// response, which they sign, is not.
			preauth = preauthExtend(ex.preauth, msg)
		}
		var done []byte
		if ex.spnego {
			done = negTokenRespAccept()
		}
		return c.establishSession(h, auth.user, key, preauth, time.Time{}, done)

	default:
		return errorResponse(h, statusLogonFailure), nil
	}
}

// establishSession is the end of an authentication, whichever mechanism it was:
// the session exists from here, keyed by the key the mechanism produced. done is
// the mechanism's last token ([MS-SMB2] 3.3.5.5.3: "the output token ... MUST be
// returned in the response"), and expires is Session.ExpirationTime (step 15), or
// the zero time for infinity.
func (c *conn) establishSession(h header, user string, key, preauth []byte, expires time.Time, done []byte) ([]byte, error) {
	sess := &session{
		user:       user,
		sessionKey: key,
		signingKey: signingKeyFor(c.dialect, key, preauth),
		expires:    expires,
	}
	var flags uint16
	// [MS-SMB2] 3.3.5.5.3 step 5: the client required it, or the server does.
	sess.signingRequired = c.clientSecurityMode&signingRequired != 0 || c.srv.RequireSigning
	if c.encCapable() {
		enc, dec, err := c.deriveCipherKeys(key, preauth)
		if err != nil {
			return nil, err
		}
		sess.crypto = &sessionCrypto{enc: enc, dec: dec, cipher: c.sessionCipher()}
		// [MS-SMB2] 3.3.5.5.3 step 10: with EncryptData the session says so,
		// and from then on a request must come encrypted.
		if c.srv.EncryptData {
			sess.encryptData = true
			flags |= sessionFlagEncryptData
		}
	}
	c.mu.Lock() // the goroutines that answer later read this table
	c.sessions[h.sessionID] = sess
	c.mu.Unlock()
	c.markAuthenticated()
	c.logSession(h.sessionID, user, sess)
	// The last message of the authentication is signed even though the
	// request was not: it is the first thing a client can check, and it
	// is what proves the server holds the same key.
	reply := c.sessionSetupResponse(h, statusSuccess, flags, done)
	signMessage(c.signAlgo(), sess.signingKey, reply)
	return reply, nil
}

// An exchange is one authentication in progress: the challenge that was sent, how
// the client wraps its tokens, the pre-authentication hash so far (3.1.1), and the
// session it is re-authenticating, if it is one. A connection may have several,
// each keyed by the session id the server allocated to it ([MS-SMB2] 3.3.5.5.1: the
// session is created at the first leg, with its own PreauthIntegrityHashValue).
type exchange struct {
	challenge *challenge
	spnego    bool
	preauth   []byte
	reauth    *session
}

// maxPendingExchanges bounds the exchanges one connection may have in progress.
// Past it the OLDEST is dropped: memory stays bounded, and a peer that starts
// exchanges it never finishes has to start this many to push a real one out.
const maxPendingExchanges = 16

func (c *conn) beginExchange(id uint64, ex *exchange) {
	if c.exchanges == nil {
		c.exchanges = map[uint64]*exchange{}
	}
	if _, again := c.exchanges[id]; again {
		c.exchangeOrder = slices.DeleteFunc(c.exchangeOrder, func(x uint64) bool { return x == id })
	}
	c.exchanges[id] = ex
	c.exchangeOrder = append(c.exchangeOrder, id)
	for len(c.exchangeOrder) > maxPendingExchanges {
		delete(c.exchanges, c.exchangeOrder[0])
		c.exchangeOrder = c.exchangeOrder[1:]
	}
}

func (c *conn) endExchange(id uint64) {
	if _, ok := c.exchanges[id]; !ok {
		return
	}
	delete(c.exchanges, id)
	c.exchangeOrder = slices.DeleteFunc(c.exchangeOrder, func(x uint64) bool { return x == id })
}

// logoff ends a session and everything that lives in it ([MS-SMB2] 3.3.5.6):
// its handles are closed, its trees dropped, its pending operations ended. The
// keys are wiped by wipeAfterReply, once the reply has been signed with them.
func (c *conn) logoff(h header) []byte {
	sid := h.sessionID
	for _, of := range c.files {
		if of.session == sid {
			c.closeOpen(of)
		}
	}
	for id, t := range c.trees {
		if t.session == sid {
			delete(c.trees, id)
		}
	}
	c.mu.Lock()
	var ended []*pendingOp
	for key, op := range c.waiting {
		if op.session == sid {
			ended = append(ended, op)
			delete(c.waiting, key)
		}
	}
	delete(c.sessions, sid)
	last := len(c.sessions) == 0
	c.mu.Unlock()
	for _, op := range ended {
		op.stop()
	}
	c.endExchange(sid)
	if last && c.srv != nil {
		// Nobody is logged in on this connection any more: it counts as
		// unauthenticated again, with the clock started over.
		c.markUnauthenticated()
	}
	return simpleResponse(h, statusSuccess, 4)
}

// wipe clears the key material this session owns. The AEADs of an encrypted
// session keep their own expanded key schedules, which the standard library
// gives no way to clear.
func (s *session) wipe() {
	clear(s.sessionKey)
	clear(s.signingKey)
}

// logSession says, on the server's Logger at Debug level, what an
// authenticated session negotiated: the dialect and the signing algorithm. It is
// how a deployment reads what a given client actually got.
func (c *conn) logSession(id uint64, user string, sess *session) {
	l := slog.Default()
	if c.srv != nil && c.srv.Logger != nil {
		l = c.srv.Logger
	}
	l.Debug("smb session established", "session", id, "user", user,
		"dialect", dialectName(c.dialect), "signing", c.signAlgo().String(),
		"cipher", c.sessionCipherName(), "encrypt_data", c.srv.EncryptData && c.encCapable(),
		"signing_required", sess.signingRequired)
}

// logRefused says, at Debug level, that a request was refused and why.
func (c *conn) logRefused(h header, why string) {
	l := slog.Default()
	if c.srv != nil && c.srv.Logger != nil {
		l = c.srv.Logger
	}
	l.Debug("smb request refused", "command", h.command.String(), "session", h.sessionID, "why", why)
}

// sessionCipherName is the cipher the session's messages would use, or "none"
// when the connection cannot encrypt.
func (c *conn) sessionCipherName() string {
	if !c.encCapable() {
		return "none"
	}
	return cipherName(c.sessionCipher())
}

// logEncrypted says, once per session and on the same Logger, that a message
// really did arrive encrypted: "negotiated" is what the client offered, this is
// what it did.
func (c *conn) logEncrypted(sid uint64, sess *session) {
	l := slog.Default()
	if c.srv != nil && c.srv.Logger != nil {
		l = c.srv.Logger
	}
	l.Debug("smb first encrypted request", "session", sid, "user", sess.user,
		"cipher", cipherName(sess.crypto.cipher))
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
func (c *conn) sessionSetupResponse(h header, status uint32, flags uint16, sec []byte) []byte {
	const bodyLen = 8 // structure size says 9 for "and a buffer"
	b := append(responseTo(h, status), make([]byte, bodyLen+len(sec))...)
	body := b[headerLen:]
	binary.LittleEndian.PutUint16(body[0:], 9)
	binary.LittleEndian.PutUint16(body[2:], flags) // session flags: not guest, not null
	binary.LittleEndian.PutUint16(body[4:], headerLen+bodyLen)
	binary.LittleEndian.PutUint16(body[6:], uint16(len(sec)))
	copy(body[bodyLen:], sec)
	return b
}

// session returns the authenticated session a message belongs to.
func (c *conn) session(h header) *session {
	return c.sessions[h.sessionID]
}
