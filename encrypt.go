// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"slices"
	"sync/atomic"
)

// Encryption, [MS-SMB2] 2.2.41 (TRANSFORM_HEADER), 3.1.4.3 and 3.3.4.1.4
// (encrypting), 3.3.5.2.1.1 (decrypting), 3.3.5.2.9 and 3.3.5.2.11 (when it is
// required), 3.3.5.5.3 (the keys).
//
// An encrypted message is a 52-byte TRANSFORM_HEADER and then the whole SMB2
// message, header included, as ciphertext. The authentication tag travels in the
// header's Signature field, and the 32 bytes of the header after it (nonce,
// original size, flags, session id) are the additional authenticated data.

// The Ciphers ids of SMB2_ENCRYPTION_CAPABILITIES ([MS-SMB2] 2.2.3.1.2). 3.0
// and 3.0.2 have no negotiation and use AES-128-CCM.
const (
	cipherNone      uint16 = 0
	cipherAES128CCM uint16 = 1
	cipherAES128GCM uint16 = 2
	cipherAES256CCM uint16 = 3
	cipherAES256GCM uint16 = 4
)

// capEncryption is SMB2_GLOBAL_CAP_ENCRYPTION, which 3.0 and 3.0.2 speak: a
// client sets it to say it can encrypt, and a server to say the same.
const capEncryption uint32 = 0x00000040

// shareFlagEncryptData is SMB2_SHAREFLAG_ENCRYPT_DATA in a TREE_CONNECT
// response, and sessionFlagEncryptData is SMB2_SESSION_FLAG_ENCRYPT_DATA in a
// SESSION_SETUP response.
const (
	shareFlagEncryptData   uint32 = 0x00008000
	sessionFlagEncryptData uint16 = 0x0004
)

// The TRANSFORM_HEADER layout.
const (
	transformLen    = 52
	offTrSignature  = 4  // the tag
	offTrNonce      = 20 // 16 bytes; 11 (CCM) or 12 (GCM) used
	offTrOrigSize   = 36
	offTrFlags      = 42 // Flags (3.1.1) / EncryptionAlgorithm (3.0, 3.0.2): 1
	offTrSessionID  = 44
	transformFlagOn = 0x0001
)

// transformProtocolID is 0xFD 'S' 'M' 'B', where an SMB2 header has 0xFE.
var transformProtocolID = [4]byte{0xFD, 'S', 'M', 'B'}

// cipherPreference is the order the server picks from a client's list. The
// 128-bit ciphers come first because every client that encrypts has one, and GCM
// before CCM because it is the faster of the two.
var cipherPreference = []uint16{cipherAES128GCM, cipherAES128CCM, cipherAES256GCM, cipherAES256CCM}

// chooseCipher is the cipher this server uses of those a client offered, or
// cipherNone when there is nothing in common ([MS-SMB2] 3.3.5.4: "the server
// MUST set Connection.CipherId to 0").
func chooseCipher(offered []uint16) uint16 {
	for _, ours := range cipherPreference {
		if slices.Contains(offered, ours) {
			return ours
		}
	}
	return cipherNone
}

// cipherKeyBits is the length of the key a cipher takes, which is also the L of
// the KDF that derives it ([MS-SMB2] 3.1.4.2).
func cipherKeyBits(id uint16) uint32 {
	if id == cipherAES256CCM || id == cipherAES256GCM {
		return 256
	}
	return 128
}

func cipherName(id uint16) string {
	switch id {
	case cipherAES128CCM:
		return "AES-128-CCM"
	case cipherAES128GCM:
		return "AES-128-GCM"
	case cipherAES256CCM:
		return "AES-256-CCM"
	case cipherAES256GCM:
		return "AES-256-GCM"
	}
	return "none"
}

// newCipherAEAD makes the AEAD a cipher id names, keyed.
func newCipherAEAD(id uint16, key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	switch id {
	case cipherAES128CCM, cipherAES256CCM:
		return newCCM(b, 11, 16)
	case cipherAES128GCM, cipherAES256GCM:
		return cipher.NewGCM(b)
	}
	return nil, errors.New("smb: no such cipher")
}

// encCapable says whether this connection can encrypt: the server offers it and
// the client agreed to it, by the capability bit before 3.1.1 and by a cipher in
// common from 3.1.1 on.
func (c *conn) encCapable() bool {
	switch c.dialect {
	case dialect300, dialect302:
		return !c.srv.DisableEncryption && c.clientCapabilities&capEncryption != 0
	case dialect311:
		return c.cipherID != cipherNone
	}
	return false
}

// sessionCipher is the cipher a session's messages use: AES-128-CCM before
// 3.1.1, and the negotiated one from it ([MS-SMB2] 3.1.4.3).
func (c *conn) sessionCipher() uint16 {
	if c.dialect == dialect311 {
		return c.cipherID
	}
	return cipherAES128CCM
}

// deriveCipherKeys makes the two keys of an encrypted session, one per
// direction ([MS-SMB2] 3.3.5.5.3 step 11): the server's EncryptionKey, which
// protects what it sends, and its DecryptionKey, which opens what it receives.
//
//	3.1.1   labels SMBS2CCipherKey and SMBC2SCipherKey, the preauth hash as context
//	before  label SMB2AESCCM for both, contexts "ServerOut" and "ServerIn "
//
// The key derivation key is the session key; NTLM has no longer one, so the
// 256-bit ciphers take a 256-bit output of the same 128-bit input.
func (c *conn) deriveCipherKeys(sessionKey, preauth []byte) (enc, dec cipher.AEAD, err error) {
	return c.deriveCipherKeysFull(sessionKey, nil, preauth)
}

// deriveCipherKeysFull is deriveCipherKeys for a mechanism that has a key longer
// than the 16 bytes of Session.SessionKey (Kerberos with AES256: 32). [MS-SMB2]
// 3.3.5.5.3 step 11: "If Connection.Dialect is 3.1.1 and Connection.CipherId is
// AES-256-CCM or AES-256-GCM, Session.FullSessionKey [is] the key derivation key.
// Otherwise, Session.SessionKey". A nil fullKey is the session key itself.
func (c *conn) deriveCipherKeysFull(sessionKey, fullKey, preauth []byte) (enc, dec cipher.AEAD, err error) {
	id := c.sessionCipher()
	bits := cipherKeyBits(id)
	if c.dialect == dialect311 && bits == 256 && len(fullKey) > 0 {
		sessionKey = fullKey
	}
	var ek, dk []byte
	if c.dialect == dialect311 {
		ek = kdf(sessionKey, "SMBS2CCipherKey\x00", string(preauth), bits)
		dk = kdf(sessionKey, "SMBC2SCipherKey\x00", string(preauth), bits)
	} else {
		ek = kdf(sessionKey, "SMB2AESCCM\x00", "ServerOut\x00", bits)
		dk = kdf(sessionKey, "SMB2AESCCM\x00", "ServerIn \x00", bits)
	}
	if enc, err = newCipherAEAD(id, ek); err != nil {
		return nil, nil, err
	}
	dec, err = newCipherAEAD(id, dk)
	return enc, dec, err
}

// A sessionCrypto is what a session needs to encrypt and decrypt.
type sessionCrypto struct {
	enc, dec cipher.AEAD
	cipher   uint16
	// nonces numbers the messages the server encrypts. A nonce must never repeat
	// under one key, and the key is per session, so a counter per session is
	// exactly enough.
	nonces atomic.Uint64
	// seen is set by the first message that arrived encrypted, so that the fact
	// is logged once and not per message.
	seen atomic.Bool
}

// nonce is the next 16-byte Nonce field for this session: an 8-byte counter and
// zeros, which are the 11 (CCM) or 12 (GCM) bytes the cipher uses and the
// reserved bytes after them.
func (sc *sessionCrypto) nonce() []byte {
	n := make([]byte, 16)
	binary.LittleEndian.PutUint64(n, sc.nonces.Add(1))
	return n
}

// seal wraps a plaintext SMB2 message (or compounded chain) in a
// TRANSFORM_HEADER for session sid.
func (sc *sessionCrypto) seal(sid uint64, plain []byte) []byte {
	out := make([]byte, transformLen, transformLen+len(plain)+sc.enc.Overhead())
	copy(out, transformProtocolID[:])
	copy(out[offTrNonce:], sc.nonce())
	binary.LittleEndian.PutUint32(out[offTrOrigSize:], uint32(len(plain)))
	binary.LittleEndian.PutUint16(out[offTrFlags:], transformFlagOn)
	binary.LittleEndian.PutUint64(out[offTrSessionID:], sid)
	sealed := sc.enc.Seal(nil, out[offTrNonce:offTrNonce+sc.enc.NonceSize()], plain, out[offTrNonce:transformLen])
	n := len(sealed) - sc.enc.Overhead()
	copy(out[offTrSignature:], sealed[n:]) // the tag goes in the Signature field
	return append(out, sealed[:n]...)
}

// errTransform ends a connection that sent a transform header it cannot use:
// every failure of [MS-SMB2] 3.3.5.2.1.1 is "disconnect the connection".
var errTransform = errors.New("smb: unusable TRANSFORM_HEADER")

// open decrypts a transformed message and returns the plaintext. The caller has
// found the session.
func (sc *sessionCrypto) open(msg []byte) ([]byte, error) {
	ns := sc.dec.NonceSize()
	sealed := append(append([]byte(nil), msg[transformLen:]...), msg[offTrSignature:offTrSignature+sc.dec.Overhead()]...)
	plain, err := sc.dec.Open(nil, msg[offTrNonce:offTrNonce+ns], sealed, msg[offTrNonce:transformLen])
	if err != nil {
		return nil, errTransform
	}
	if int(binary.LittleEndian.Uint32(msg[offTrOrigSize:])) != len(plain) {
		return nil, errTransform
	}
	return plain, nil
}

// transformSession reads what a TRANSFORM_HEADER must say before the message
// can be decrypted: that it is long enough to have a body, that its flags say
// "encrypted", and which session it is for.
func transformSession(msg []byte) (uint64, error) {
	if len(msg) <= transformLen || [4]byte(msg[:4]) != transformProtocolID {
		return 0, errTransform
	}
	if binary.LittleEndian.Uint16(msg[offTrFlags:]) != transformFlagOn {
		return 0, errTransform
	}
	return binary.LittleEndian.Uint64(msg[offTrSessionID:]), nil
}

// decryptFrame opens a transformed frame for the session its header names.
func (c *conn) decryptFrame(msg []byte) (plain []byte, sid uint64, err error) {
	sid, err = transformSession(msg)
	if err != nil {
		return nil, 0, err
	}
	sess := c.sessions[sid]
	if sess == nil || sess.crypto == nil {
		return nil, 0, errTransform
	}
	plain, err = sess.crypto.open(msg)
	if err != nil {
		return nil, 0, err
	}
	// 3.3.5.2.1.1: what comes out must be an SMB2 message, not a compressed one
	// (compression is not negotiated) and not nothing.
	if len(plain) < headerLen || [4]byte(plain[:4]) != protocolID {
		return nil, 0, errTransform
	}
	if sess.crypto.seen.CompareAndSwap(false, true) {
		c.logEncrypted(sid, sess)
	}
	return plain, sid, nil
}
