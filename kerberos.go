// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"bytes"
	"errors"
	"time"
)

// Acceptor verifies a Kerberos AP-REQ for the server. The embedder provides it,
// which keeps this module free of a Kerberos library: a keytab-backed one is
// about forty lines over go-authn/krb5 or gokrb5.
//
// Accept is handed the GSS-API token of RFC 4121 section 4.1 -- the InitialContextToken
// that carries the AP-REQ -- always framed with the Kerberos V5 OID
// (1.2.840.113554.1.2.2): the server has already rewritten the Microsoft OID a
// Windows client sends, so an implementation never sees it. It returns who the
// client is, the token to send back (the AP-REP when the client asked for mutual
// authentication, which Windows always does; framed with the same OID), and an
// error that refuses the client. Accept may be called by several connections at
// once. Replay detection (RFC 4120 section 3.2.3) belongs to it, since it holds
// the replay cache.
type Acceptor interface {
	Accept(token []byte) (*Accepted, []byte, error)
}

// Accepted is what a successful [Acceptor.Accept] establishes.
type Accepted struct {
	// User is the name the server's access rules see: the one a share's allow and
	// writers lists name, and the one [Server.Access] receives. Mapping a principal
	// to it is the EMBEDDER's decision (alice@EXAMPLE.ORG and alice@PARTNER.ORG are
	// different people), and an unknown principal is refused by returning an error
	// from Accept, never by returning an empty or default User.
	User string
	// Principal is who the client proved to be, in full ("alice@EXAMPLE.ORG"), for
	// the log.
	Principal string
	// Key is the GSS-API context key: the acceptor's subkey if the AP-REP carried
	// one, else the initiator's authenticator subkey, else the ticket's session key
	// (RFC 4121 section 2; [MS-KILE] 3.1.1.2 says the AP-REP's subkey is the
	// session key when mutual authentication is requested). It is a secret; the server uses its first 16 bytes
	// as Session.SessionKey ([MS-SMB2] 3.3.5.5.3 step 6, [MS-KILE] 3.1.1.2) and
	// wipes its copy when the session ends.
	Key []byte
	// Expires is when the ticket stops being valid, or the zero time for never. The
	// session then expires ([MS-SMB2] 3.3.5.5.3 step 15) and the client has to
	// authenticate again.
	Expires time.Time
}

// ErrNeedKerberos is what [Server.Serve] returns when NTLM is disabled and no
// Kerberos acceptor is set: a server that accepts neither would refuse every
// client, and the mistake belongs at start-up rather than in the first client's
// logon failure.
var ErrNeedKerberos = errors.New("smb: DisableNTLM needs a Kerberos acceptor, or nobody can log in")

// krbToken splits a GSS-API InitialContextToken, APPLICATION 0 { OID, rest }
// (RFC 2743 section 3.1), and says whether the OID is one of the two Kerberos ones.
func krbToken(token []byte) (oid, rest []byte, ok bool) {
	body, err := derUnwrap(token, 0x60)
	if err != nil {
		return nil, nil, false
	}
	oid, rest, err = derSplit(body, 0x06)
	if err != nil {
		return nil, nil, false
	}
	return oid, rest, bytes.Equal(oid, oidKRB5) || bytes.Equal(oid, oidMSKRB5)
}

// isKerberosToken says the mechanism token is a GSS-API Kerberos token rather
// than an NTLM message.
func isKerberosToken(token []byte) bool {
	if len(token) == 0 || token[0] != 0x60 {
		return false
	}
	_, _, ok := krbToken(token)
	return ok
}

// withMech re-frames a GSS-API token with another mechanism OID.
func withMech(rest, oid []byte) []byte { return derApp(0, append(derOID(oid), rest...)) }

// sessionKey16 is Session.SessionKey: the first 16 bytes of the GSS key, zero
// padded when it is shorter ([MS-SMB2] 3.3.5.5.3 step 6 and 3.3.1.8).
func sessionKey16(key []byte) []byte {
	out := make([]byte, 16)
	copy(out, key)
	return out
}

// sessionSetupKerberos is SESSION_SETUP with a Kerberos mechanism token: one
// round trip, so the answer is final. msg is the whole request (3.1.1 hashes it).
func (c *conn) sessionSetupKerberos(h header, msg, token []byte, wrapped bool, existing *session) ([]byte, error) {
	acc := c.srv.Kerberos
	if acc == nil {
		c.logRefused(h, "a Kerberos token, and no Kerberos acceptor is configured")
		return errorResponse(h, statusLogonFailure), nil
	}
	clientOID, rest, _ := krbToken(token)
	got, apRep, err := acc.Accept(withMech(rest, oidKRB5))
	if err != nil || got == nil || got.User == "" || len(got.Key) == 0 {
		// The same status whatever refused it: a stranger learns neither which
		// principals exist nor which check failed. The reason goes to the log.
		if err != nil {
			c.logRefused(h, "Kerberos: "+err.Error())
		} else {
			c.logRefused(h, "Kerberos: the acceptor returned no user or no key")
		}
		return errorResponse(h, statusLogonFailure), nil
	}
	defer clear(got.Key)
	// The AP-REP goes back in the OID the client used.
	var reply []byte
	if len(apRep) > 0 {
		if _, r, ok := krbToken(apRep); ok {
			apRep = withMech(r, clientOID)
		}
		reply = apRep
	}
	var done []byte
	if wrapped {
		done = negTokenRespKerberos(clientOID, reply)
	} else {
		done = reply
	}

	if existing != nil {
		// Authenticating again, as the same session ([MS-SMB2] 3.3.5.5): the same
		// user, the keys and handles untouched, only the expiry moves.
		if got.User != existing.user {
			return errorResponse(h, statusAccessDenied), nil
		}
		existing.expires = got.Expires
		var flags uint16
		if existing.encryptData {
			flags |= sessionFlagEncryptData
		}
		out := c.sessionSetupResponse(h, statusSuccess, flags, done)
		signMessage(c.signAlgo(), existing.signingKey, out)
		return out, nil
	}

	// A new session. The id is the server's choice, as in the first leg of NTLM;
	// a client that names one has to be naming an exchange of this connection.
	id := h.sessionID
	if id == 0 {
		for {
			c.nextID++
			if c.nextID != 0 && c.sessions[c.nextID] == nil && c.exchanges[c.nextID] == nil {
				break
			}
		}
		id = c.nextID
	} else {
		c.endExchange(id)
	}
	h.sessionID = id
	var preauth []byte
	if c.dialect == dialect311 {
		// One request, no earlier response: [MS-SMB2] 3.3.5.5.3 step 1 hashes the
		// request, and the final response is signed with the key this produces.
		preauth = preauthExtend(c.preauth, msg)
	}
	return c.establishSession(h, got.User, sessionKey16(got.Key), preauth, got.Expires, done)
}
