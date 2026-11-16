// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// Signing is what makes a message provably from the party that authenticated,
// and it is not optional in practice: Windows 11 requires it of every
// connection by default, so a server that cannot sign cannot be mounted by the
// client this package exists for.
//
// Three algorithms, chosen by dialect and, for 3.1.1, by the SIGNING_CAPABILITIES
// negotiate context ([MS-SMB2] 3.1.4.1, "Signing An Outgoing Message"):
//
//	2.0.2, 2.1        HMAC-SHA256, keyed with the session key itself
//	3.0, 3.0.2        AES-CMAC, keyed with a key DERIVED from it
//	3.1.1             AES-CMAC, or AES-GMAC when the client offered it
//
// The signature covers the whole message with its own signature field zeroed,
// which is why signing is the last thing done to a reply and verification the
// first thing done to a request.

// A sigAlgo is how one connection signs.
type sigAlgo uint8

const (
	sigHMAC sigAlgo = iota // HMAC-SHA256, truncated to 16 bytes: 2.0.2 and 2.1
	sigCMAC                // AES-128-CMAC, RFC 4493: 3.0, 3.0.2, and 3.1.1 by default
	sigGMAC                // AES-128-GMAC, RFC 4543: 3.1.1 only, by negotiate context
)

// The SigningAlgorithms ids of SMB2_SIGNING_CAPABILITIES ([MS-SMB2] 2.2.3.1.7).
const (
	signIDHMACSHA256 uint16 = 0
	signIDAESCMAC    uint16 = 1
	signIDAESGMAC    uint16 = 2
)

// sigAlgoFor is the algorithm a connection signs with, given its dialect and
// the signing algorithm id negotiated for it (see negotiate.go; 1, AES-CMAC,
// when none was).
func sigAlgoFor(dialect uint16, negotiated uint16) sigAlgo {
	switch dialect {
	case dialect300, dialect302:
		return sigCMAC
	case dialect311:
		if negotiated == signIDAESGMAC {
			return sigGMAC
		}
		return sigCMAC
	default:
		return sigHMAC
	}
}

// signAlgo is the algorithm this connection signs with.
func (c *conn) signAlgo() sigAlgo { return sigAlgoFor(c.dialect, c.signingAlgorithm) }

// signingKeyFor derives the key a dialect signs with. preauth is the
// pre-authentication integrity hash of 3.1.1 (see preauth.go), and is ignored by
// the dialects before it.
//
// [MS-SMB2] 3.3.5.5.3, step 7: label "SMBSigningKey" and the preauth hash for
// 3.1.1, label "SMB2AESCMAC" and context "SmbSign" before it.
func signingKeyFor(dialect uint16, sessionKey, preauth []byte) []byte {
	switch dialect {
	case dialect311:
		return kdf(sessionKey, "SMBSigningKey\x00", string(preauth), 128)
	case dialect300, dialect302:
		return kdf(sessionKey, "SMB2AESCMAC\x00", "SmbSign\x00", 128)
	default:
		return sessionKey
	}
}

// kdf is NIST SP 800-108 in counter mode over HMAC-SHA256, which is how SMB 3
// derives every key it uses from the session key ([MS-SMB2] 3.1.4.2: r = 32,
// the PRF HMAC-SHA256, L the key length in bits). 128 and 256 are the lengths
// SMB asks for, and one PRF output (256 bits) is enough for both, so the
// counter is always 1.
func kdf(key []byte, label, context string, bits uint32) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte{0x00, 0x00, 0x00, 0x01}) // i
	h.Write([]byte(label))                  // includes its terminating zero
	h.Write([]byte{0x00})                   // the separator
	h.Write([]byte(context))                // 3.0: with its zero; 3.1.1: the preauth hash
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], bits) // L, in bits
	h.Write(l[:])
	return h.Sum(nil)[:bits/8]
}

// gmacNonce is the 12-byte nonce of an AES-GMAC signature ([MS-SMB2] 3.1.4.1):
// the MessageId, then 4 bytes whose least significant bit says the sender is the
// server and whose next bit says the message is an SMB2 CANCEL request.
//
// Everything it needs is in the message itself, so a signature can be made or
// checked from the bytes alone.
func gmacNonce(msg []byte) []byte {
	n := make([]byte, 12)
	copy(n, msg[offMessageID:offMessageID+8])
	flags := binary.LittleEndian.Uint32(msg[offFlags:])
	var tail uint32
	if flags&flagServerToRedir != 0 {
		tail |= 1
	} else if command(binary.LittleEndian.Uint16(msg[offCommand:])) == cmdCancel {
		tail |= 2
	}
	binary.LittleEndian.PutUint32(n[8:], tail)
	return n
}

// gmacSum is AES-GMAC (RFC 4543): AES-GCM over no plaintext, the message as
// the additional data, and the 16-byte tag as the signature.
func gmacSum(key, nonce, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	return g.Seal(nil, nonce, nil, msg)
}

// signatureOf computes the signature a message should carry. The caller has
// already zeroed the field, or is about to compare against what is in it.
func signatureOf(alg sigAlgo, key, msg []byte) []byte {
	switch alg {
	case sigGMAC:
		return gmacSum(key, gmacNonce(msg), msg)
	case sigCMAC:
		return cmacSum(key, msg)
	default:
		mac := hmac.New(sha256.New, key)
		mac.Write(msg)
		return mac.Sum(nil)[:16]
	}
}

// signMessage writes the signature into a reply, and says so in its flags.
func signMessage(alg sigAlgo, key, msg []byte) {
	if len(msg) < headerLen || len(key) == 0 {
		return
	}
	flags := binary.LittleEndian.Uint32(msg[offFlags:]) | flagSigned
	binary.LittleEndian.PutUint32(msg[offFlags:], flags)
	clear(msg[offSignature : offSignature+16])
	copy(msg[offSignature:], signatureOf(alg, key, msg))
}

// verifyMessage checks the signature a request carries.
//
// The message is copied before its signature field is zeroed, because the
// caller still has to read the request afterwards -- and a verifier that
// scribbles on its input is a verifier that changes what it verified.
func verifyMessage(alg sigAlgo, key, msg []byte) bool {
	if len(msg) < headerLen || len(key) == 0 {
		return false
	}
	want := append([]byte(nil), msg[offSignature:offSignature+16]...)
	scratch := append([]byte(nil), msg...)
	clear(scratch[offSignature : offSignature+16])
	return hmac.Equal(want, signatureOf(alg, key, scratch))
}
