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
	// Key is the GSS-API context key, at least 16 bytes (a shorter one refuses the
	// client). WHICH key matters, because the client derives its signing key from
	// the same one and a different key signs fine here and fails every request there:
	//
	//   - mutual authentication requested (Windows always does): the acceptor's
	//     subkey, the one the AP-REP carries. [MS-KILE] 3.1.1.2: "The subkey in the
	//     EncAPRepPart of the KRB_AP_REP message ... is used as the session key
	//     when MutualAuthentication is requested", and with AES "the subkeys are
	//     different and the subkey in the KRB_AP_REP message is used" (not the
	//     AP-REQ's). So an acceptor must put a subkey in its AP-REP and return it.
	//   - otherwise: the initiator's authenticator subkey, else the ticket's
	//     session key (RFC 4121 section 2).
	//
	// The server uses the first 16 bytes as Session.SessionKey and, on 3.1.1 with
	// an AES-256 cipher, the whole key as Session.FullSessionKey ([MS-SMB2]
	// 3.3.5.5.3 steps 6 and 11). It is a secret. The server copies it and wipes
	// its copy; the slice stays yours, and wiping it is yours too.
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

// minContextKey is the shortest GSS key accepted: every Kerberos encryption type
// that can carry SMB (AES128, AES256, RC4) has one of 16 bytes or more, and a
// shorter one would be zero-padded into a weaker session key than the client's.
const minContextKey = 16

// sessionKey16 is Session.SessionKey: the first 16 bytes of the GSS key
// ([MS-SMB2] 3.3.5.5.3 step 6 and 3.3.1.8). The caller has checked it has them.
func sessionKey16(key []byte) []byte {
	out := make([]byte, 16)
	copy(out, key)
	return out
}

// sessionSetupKerberos is SESSION_SETUP with a Kerberos mechanism token: one
// round trip, so the answer is final. msg is the whole request (3.1.1 hashes it).
func (c *conn) sessionSetupKerberos(h header, msg, blob, token []byte, wrapped bool, existing *session) ([]byte, error) {
	acc := c.srv.Kerberos
	if acc == nil {
		c.logRefused(h, "a Kerberos token, and no Kerberos acceptor is configured")
		return errorResponse(h, statusLogonFailure), nil
	}
	// RFC 4178 section 3.2 (c) II and section 5: a token for a mechanism that is
	// not the client's FIRST choice makes the mechListMIC exchange mandatory, and
	// this server neither sends nor checks one. So a Kerberos token behind a list
	// that starts with anything else (NTLMSSP, say: a client that prefers it and
	// could be walked down to Kerberos, or the reverse) is refused rather than
	// accepted unprotected. A bare token names no list and has no MIC to skip.
	if wrapped {
		if m := firstMechType(blob); !bytes.Equal(m, oidKRB5) && !bytes.Equal(m, oidMSKRB5) {
			c.logRefused(h, "Kerberos token, but the client's first mechanism is not Kerberos (the mechListMIC would be required)")
			return errorResponse(h, statusLogonFailure), nil
		}
	}
	clientOID, rest, _ := krbToken(token)
	got, apRep, err := acc.Accept(withMech(rest, oidKRB5))
	if err != nil || got == nil || got.User == "" || len(got.Key) < minContextKey {
		// The same status whatever refused it: a stranger learns neither which
		// principals exist nor which check failed. The reason goes to the log.
		switch {
		case err != nil:
			c.logRefused(h, "Kerberos: "+err.Error())
		case got != nil && got.User != "" && len(got.Key) < minContextKey:
			c.logRefused(h, "Kerberos: the acceptor returned a key shorter than 16 bytes")
		default:
			c.logRefused(h, "Kerberos: the acceptor returned no user or no key")
		}
		return errorResponse(h, statusLogonFailure), nil
	}
	// The embedder owns got.Key: work on a copy, and wipe only that.
	key := bytes.Clone(got.Key)
	defer clear(key)
	// A ticket that has already run out would make a session that is expired from
	// birth ([MS-SMB2] 3.3.5.5.3 step 15 sets ExpirationTime from the GSS context,
	// and every later request would answer SESSION_EXPIRED).
	if !got.Expires.IsZero() && !time.Now().Before(got.Expires) {
		c.logRefused(h, "Kerberos: the ticket has already expired")
		return errorResponse(h, statusLogonFailure), nil
	}
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
		// supportedMech is the client's FIRST mechanism, which the token belongs to
		// (checked above to be a Kerberos one; see firstMechType).
		done = negTokenRespKerberos(firstMechType(blob), reply)
	} else {
		done = reply
	}

	if existing != nil {
		// Authenticating again, as the same session ([MS-SMB2] 3.3.5.5): the same
		// user, the keys and handles untouched, only the expiry moves.
		if got.User != existing.user {
			return errorResponse(h, statusAccessDenied), nil
		}
		c.mu.Lock() // the request loop reads it from other goroutines
		existing.expires = got.Expires
		c.mu.Unlock()
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
	// Session.SessionKey is the first 16 bytes; the whole key is Session.FullSessionKey,
	// which 3.1.1 with an AES-256 cipher derives its encryption keys from
	// ([MS-SMB2] 3.3.5.5.3 steps 6 and 11).
	return c.establishSession(h, got.User, sessionKey16(key), key, preauth, got.Expires, done)
}
