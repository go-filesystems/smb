// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

// The CLIENT side of NTLMv2 ([MS-NLMP] 3.1.5): the server side lives in ntlm.go.
// SMB uses NTLM for authentication only, so no sealing and no per-message
// signing of its own: the SMB2 signature is made with the ExportedSessionKey.

const (
	avFlags          uint16 = 0x0006
	avTargetName     uint16 = 0x0009
	avChannelBind    uint16 = 0x000A
	avFlagMICPresent        = 0x00000002
)

// clNTLM is one NTLMv2 exchange of a client.
type clNTLM struct {
	user, password, domain, spn string
	negotiate                   []byte // type 1, as sent: the MIC covers it
	exported                    []byte // ExportedSessionKey, set by authenticate
	keyExch                     bool   // key exchange was negotiated, set by authenticate
}

func newCLNTLM(user, password, domain, spn string) *clNTLM {
	return &clNTLM{user: user, password: password, domain: domain, spn: spn}
}

// type1 builds NEGOTIATE_MESSAGE.
func (n *clNTLM) type1() []byte {
	flags := ntlmNegotiateUnicode | ntlmRequestTarget | ntlmNegotiateSign | ntlmNegotiateNTLM |
		ntlmNegotiateAlwaysSign | ntlmNegotiateExtSecurity | ntlmNegotiateVersion |
		ntlmNegotiate128 | ntlmNegotiateKeyExchange | ntlmNegotiate56 | ntlmNegotiateTargetInfo
	b := make([]byte, 40)
	copy(b, ntlmSignature[:])
	binary.LittleEndian.PutUint32(b[8:], ntlmNegotiate)
	binary.LittleEndian.PutUint32(b[12:], flags)
	copy(b[32:], []byte{10, 0, 0x63, 0x45, 0, 0, 0, 15}) // Version: 10.0 build 17763, revision 15
	n.negotiate = b
	return b
}

type clChallenge struct {
	flags      uint32
	nonce      [8]byte
	targetInfo []byte
}

// parseChallenge reads CHALLENGE_MESSAGE; every field is bounds-checked.
func parseChallenge(b []byte) (clChallenge, error) {
	var c clChallenge
	if len(b) < 48 || !bytes.HasPrefix(b, ntlmSignature[:]) || le32(b[8:]) != ntlmChallenge {
		return c, errNotNTLM
	}
	c.flags = le32(b[20:])
	copy(c.nonce[:], b[24:32])
	n, off := int(le16(b[40:])), int(le32(b[44:]))
	if n > 0 {
		if off < 48 || off > len(b) || n > len(b)-off {
			return c, fmt.Errorf("%w: target info outside the message", errNotNTLM)
		}
		c.targetInfo = b[off : off+n]
	}
	if c.flags&ntlmNegotiateUnicode == 0 {
		return c, errors.New("smb: the server's NTLM challenge does not offer Unicode")
	}
	return c, nil
}

// avPairs splits target info into (id, value) pairs, up to the EOL. A pair that
// runs past the end is an error: the NTLMv2 response is computed over these
// bytes and signing garbage back is how a downgrade would hide.
func avPairs(b []byte) (ids []uint16, vals [][]byte, err error) {
	for {
		if len(b) < 4 {
			return nil, nil, errNotNTLM
		}
		id, n := le16(b), int(le16(b[2:]))
		if n > len(b)-4 {
			return nil, nil, errNotNTLM
		}
		if id == avEOL {
			return ids, vals, nil
		}
		ids, vals = append(ids, id), append(vals, b[4:4+n])
		b = b[4+n:]
	}
}

// authenticate answers the challenge with AUTHENTICATE_MESSAGE and records the
// ExportedSessionKey. The MIC is included whenever the server's target info
// carries a timestamp, as [MS-NLMP] 3.1.5.1.2 requires, so a server that
// demands it (Windows) and one that ignores it (Samba) are both satisfied.
func (n *clNTLM) authenticate(chalMsg []byte, c clChallenge) ([]byte, error) {
	ids, vals, err := avPairs(c.targetInfo)
	if err != nil {
		return nil, err
	}
	var ts []byte
	var info bytes.Buffer
	flagsSeen := false
	for i, id := range ids {
		v := vals[i]
		switch id {
		case avTimestamp:
			ts = v
		case avFlags:
			flagsSeen = true
			if len(v) == 4 {
				v = binary.LittleEndian.AppendUint32(nil, le32(v)|avFlagMICPresent)
			}
		case avTargetName, avChannelBind:
			continue // replaced below
		}
		putAV(&info, id, v)
	}
	mic := ts != nil
	if mic && !flagsSeen {
		putAV(&info, avFlags, binary.LittleEndian.AppendUint32(nil, avFlagMICPresent))
	}
	putAV(&info, avTargetName, utf16leBytes(n.spn))
	putAV(&info, avChannelBind, make([]byte, 16)) // no channel bindings: sixteen zeros
	putAV(&info, avEOL, nil)

	var clientNonce [8]byte
	rand.Read(clientNonce[:]) // crypto/rand.Read cannot return an error: it ends the program instead
	stamp := ts
	if stamp == nil {
		stamp = filetimeBytes(time.Now())
	}
	temp := append([]byte{1, 1, 0, 0, 0, 0, 0, 0}, stamp...)
	temp = append(temp, clientNonce[:]...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, info.Bytes()...)
	temp = append(temp, 0, 0, 0, 0)

	key := ntowfv2(n.user, n.domain, credential{password: n.password})
	m := hmac.New(md5.New, key)
	m.Write(c.nonce[:])
	m.Write(temp)
	proof := m.Sum(nil)
	nt := append(append([]byte(nil), proof...), temp...)
	base := hmac.New(md5.New, key)
	base.Write(proof)
	baseKey := base.Sum(nil)

	lm := make([]byte, 24) // [MS-NLMP] 3.1.5.1.2: zeros when the server sent a timestamp
	if ts == nil {
		lmm := hmac.New(md5.New, key)
		lmm.Write(c.nonce[:])
		lmm.Write(clientNonce[:])
		lm = append(lmm.Sum(nil), clientNonce[:]...)
	}

	flags := ntlmNegotiateUnicode | ntlmNegotiateNTLM | ntlmNegotiateExtSecurity | ntlmNegotiateVersion |
		ntlmNegotiate128 | ntlmNegotiate56 | ntlmNegotiateSign | ntlmNegotiateAlwaysSign | ntlmRequestTarget
	var encKey []byte
	n.exported = baseKey
	if c.flags&ntlmNegotiateKeyExchange != 0 {
		flags |= ntlmNegotiateKeyExchange
		n.exported = make([]byte, 16)
		rand.Read(n.exported)
		rc, _ := rc4.NewCipher(baseKey) // a 16-byte key is always a valid RC4 key

		encKey = make([]byte, 16)
		rc.XORKeyStream(encKey, n.exported)
	}

	dom, usr, ws := utf16leBytes(n.domain), utf16leBytes(n.user), utf16leBytes("")
	const fixed = 88
	msg := make([]byte, fixed, fixed+len(lm)+len(nt)+len(dom)+len(usr)+len(encKey))
	copy(msg, ntlmSignature[:])
	binary.LittleEndian.PutUint32(msg[8:], ntlmAuth)
	field := func(at int, data []byte) {
		putField(msg[at:], len(data), uint32(len(msg)))
		msg = append(msg, data...)
	}
	field(12, lm)
	field(20, nt)
	field(28, dom)
	field(36, usr)
	field(44, ws)
	field(52, encKey)
	binary.LittleEndian.PutUint32(msg[60:], flags)
	copy(msg[64:], []byte{10, 0, 0x63, 0x45, 0, 0, 0, 15})
	if mic {
		h := hmac.New(md5.New, n.exported)
		h.Write(n.negotiate)
		h.Write(chalMsg)
		h.Write(msg)
		copy(msg[72:], h.Sum(nil))
	}
	n.keyExch = flags&ntlmNegotiateKeyExchange != 0
	return msg, nil
}

// ntlmMIC is the NTLMSSP signature of msg at sequence number 0 with the
// extended-session-security rules of [MS-NLMP] 3.4.4.2, which SPNEGO's
// mechListMIC ([MS-SPNG] 3.1.5.1) uses: version 1, the first 8 bytes of
// HMAC_MD5(SigningKey, SeqNum || msg) (encrypted with the sealing key's RC4 when
// key exchange was negotiated), and the sequence number. toServer picks the
// direction's keys.
func ntlmMIC(exported []byte, keyExch, toServer bool, msg []byte) []byte {
	dir := "server-to-client"
	if toServer {
		dir = "client-to-server"
	}
	signKey := md5.Sum(append(slices.Clone(exported), "session key to "+dir+" signing key magic constant\x00"...))
	m := hmac.New(md5.New, signKey[:])
	m.Write(make([]byte, 4)) // SeqNum 0
	m.Write(msg)
	sum := m.Sum(nil)[:8]
	if keyExch {
		sealKey := md5.Sum(append(slices.Clone(exported), "session key to "+dir+" sealing key magic constant\x00"...))
		rc, _ := rc4.NewCipher(sealKey[:]) // 16 bytes: always a valid RC4 key
		rc.XORKeyStream(sum, sum)
	}
	return append(append(binary.LittleEndian.AppendUint32(nil, 1), sum...), 0, 0, 0, 0)
}

// mechListMIC signs the list of mechanisms this client offered.
func (n *clNTLM) mechListMIC(list []byte) []byte { return ntlmMIC(n.exported, n.keyExch, true, list) }

// serverMICOK checks the server's mechListMIC over the same list.
func (n *clNTLM) serverMICOK(mic, list []byte) bool {
	return hmac.Equal(mic, ntlmMIC(n.exported, n.keyExch, false, list))
}
