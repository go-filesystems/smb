// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"encoding/binary"
	"slices"
)

// Negotiate contexts: the list a 3.1.1 client appends to NEGOTIATE and a
// 3.1.1 server answers with, which is how the dialect gains properties without
// a new field each time ([MS-SMB2] 2.2.3.1, "SMB2 NEGOTIATE_CONTEXT Request
// Values").
//
// Bibliography (opened 2026-11-16 on learn.microsoft.com, [MS-SMB2] revision
// 88.0 of 2026-09-28): 2.2.3 (NEGOTIATE request), 2.2.3.1 and 2.2.3.1.1, 2.2.3.1.2,
// 2.2.3.1.7 (the contexts), 2.2.4 (NEGOTIATE response), 3.3.5.4 (receiving
// NEGOTIATE), 3.3.5.5, 3.3.5.5.1 and 3.3.5.5.3 (SESSION_SETUP and the
// pre-authentication hash), 3.1.4.1 (signing, with the AES-GMAC nonce), 3.1.4.2
// (key derivation), 3.3.5.15.12 (VALIDATE_NEGOTIATE_INFO). [MS-SMB2] publishes no
// cryptographic test vectors -- its section 4 examples are message layouts -- so
// the primitives are checked against RFC/NIST constructions in the tests, and the
// whole against independent clients.
//
// Each context is an 8-byte header (ContextType, DataLength, 4 reserved bytes)
// and its data; the first starts at NegotiateContextOffset, 8-byte aligned, and
// each next one at the first 8-byte-aligned offset after the previous.

// The ContextType values this server reads or writes. Every other type is
// ignored on receipt ([MS-SMB2] 3.3.5.4: "the server MUST ignore the negotiate
// context"), so a client's compression, RDMA, transport or netname context is
// skipped rather than refused.
const (
	ctxPreauthIntegrity uint16 = 0x0001
	ctxEncryption       uint16 = 0x0002
	ctxCompression      uint16 = 0x0003
	ctxRDMATransform    uint16 = 0x0007
	ctxSigning          uint16 = 0x0008
)

// maxNegotiateContexts bounds the list before a byte of it is read: a context
// is at least 8 bytes, so a count the message cannot hold is a lie, and a
// bound keeps the walk from being asked to make a very long one.
const maxNegotiateContexts = 64

// What the client offered in its negotiate contexts.
type clientContexts struct {
	hashes     []uint16 // HashAlgorithms of SMB2_PREAUTH_INTEGRITY_CAPABILITIES
	ciphers    []uint16 // Ciphers of SMB2_ENCRYPTION_CAPABILITIES, most preferred first
	signing    []uint16 // SigningAlgorithms of SMB2_SIGNING_CAPABILITIES, most preferred first
	hasCipher  bool     // an ENCRYPTION context was present
	hasSigning bool     // a SIGNING context was present
}

// parseNegotiateContexts reads the NegotiateContextList of a 3.1.1 NEGOTIATE
// request. msg is the whole request, header included, because the offsets are
// from the start of the header. It returns the status to fail the request with
// when the list breaks a rule of [MS-SMB2] 3.3.5.4: not exactly one
// PREAUTH_INTEGRITY_CAPABILITIES context, more than one of any other context
// the server reads, or a context shorter than its structure.
func parseNegotiateContexts(msg []byte, off, count int) (clientContexts, uint32) {
	var cc clientContexts
	if count <= 0 || count > maxNegotiateContexts || off < headerLen || off%8 != 0 || off > len(msg) {
		return cc, statusInvalidParameter
	}
	var preauth, enc, comp, rdma, sign int
	for i := 0; i < count; i++ {
		if off+8 > len(msg) {
			return cc, statusInvalidParameter
		}
		typ := binary.LittleEndian.Uint16(msg[off:])
		dlen := int(binary.LittleEndian.Uint16(msg[off+2:]))
		if off+8+dlen > len(msg) {
			return cc, statusInvalidParameter
		}
		data := msg[off+8 : off+8+dlen]
		switch typ {
		case ctxPreauthIntegrity:
			preauth++
			// HashAlgorithmCount, SaltLength, then the two arrays.
			if len(data) < 4 {
				return cc, statusInvalidParameter
			}
			n := int(binary.LittleEndian.Uint16(data[0:]))
			salt := int(binary.LittleEndian.Uint16(data[2:]))
			if 4+2*n+salt > len(data) {
				return cc, statusInvalidParameter
			}
			cc.hashes = readU16s(data[4:], n)
		case ctxEncryption:
			enc++
			cc.hasCipher = true
			if len(data) < 2 {
				return cc, statusInvalidParameter
			}
			n := int(binary.LittleEndian.Uint16(data[0:]))
			if 2+2*n > len(data) {
				return cc, statusInvalidParameter
			}
			cc.ciphers = readU16s(data[2:], n)
		case ctxSigning:
			sign++
			cc.hasSigning = true
			if len(data) < 2 {
				return cc, statusInvalidParameter
			}
			n := int(binary.LittleEndian.Uint16(data[0:]))
			if n == 0 || 2+2*n > len(data) {
				return cc, statusInvalidParameter
			}
			cc.signing = readU16s(data[2:], n)
		case ctxCompression:
			comp++
		case ctxRDMATransform:
			rdma++
		}
		// The next context is at the next 8-byte boundary after this one.
		off += 8 + dlen
		off = (off + 7) &^ 7
	}
	if preauth != 1 || enc > 1 || comp > 1 || rdma > 1 || sign > 1 {
		return cc, statusInvalidParameter
	}
	return cc, statusSuccess
}

// readU16s reads n little-endian uint16s; the caller has checked there are
// that many.
func readU16s(b []byte, n int) []uint16 {
	out := make([]uint16, n)
	for i := range out {
		out[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return out
}

// chooseHash picks the pre-authentication hash: SHA-512 if the client lists it,
// and false when it lists nothing the server speaks, which is
// STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP ([MS-SMB2] 3.3.5.4).
func chooseHash(offered []uint16) (uint16, bool) {
	if slices.Contains(offered, hashIDSHA512) {
		return hashIDSHA512, true
	}
	return 0, false
}

// chooseSigning picks the signing algorithm from a SIGNING_CAPABILITIES list:
// AES-GMAC when offered, since it is the faster of the two, else AES-CMAC. When
// the client offers neither (only HMAC-SHA256, which 3.x does not use) the
// answer is AES-CMAC, as [MS-SMB2] 3.3.5.4 requires.
func chooseSigning(offered []uint16) uint16 {
	if slices.Contains(offered, signIDAESGMAC) {
		return signIDAESGMAC
	}
	return signIDAESCMAC
}

// A negotiate context to put in the response: type, then data.
type outContext struct {
	typ  uint16
	data []byte
}

// appendContexts writes a NegotiateContextList onto b, which must end on an
// 8-byte boundary. Each context but the last is padded to the next boundary.
func appendContexts(b []byte, ctxs []outContext) []byte {
	for i, c := range ctxs {
		var hdr [8]byte
		binary.LittleEndian.PutUint16(hdr[0:], c.typ)
		binary.LittleEndian.PutUint16(hdr[2:], uint16(len(c.data)))
		b = append(b, hdr[:]...)
		b = append(b, c.data...)
		if i != len(ctxs)-1 {
			for len(b)%8 != 0 {
				b = append(b, 0)
			}
		}
	}
	return b
}

// preauthContext is the SMB2_PREAUTH_INTEGRITY_CAPABILITIES answer: one hash
// algorithm, the one chosen, and a salt of fresh random bytes.
func preauthContext(hash uint16, salt []byte) outContext {
	d := make([]byte, 4+2+len(salt))
	binary.LittleEndian.PutUint16(d[0:], 1)
	binary.LittleEndian.PutUint16(d[2:], uint16(len(salt)))
	binary.LittleEndian.PutUint16(d[4:], hash)
	copy(d[6:], salt)
	return outContext{ctxPreauthIntegrity, d}
}

// cipherContext is the SMB2_ENCRYPTION_CAPABILITIES answer: the one cipher
// chosen, or 0 for "none in common".
func cipherContext(id uint16) outContext {
	d := make([]byte, 4)
	binary.LittleEndian.PutUint16(d[0:], 1)
	binary.LittleEndian.PutUint16(d[2:], id)
	return outContext{ctxEncryption, d}
}

// signingContext is the SMB2_SIGNING_CAPABILITIES answer: the one algorithm
// chosen.
func signingContext(alg uint16) outContext {
	d := make([]byte, 4)
	binary.LittleEndian.PutUint16(d[0:], 1)
	binary.LittleEndian.PutUint16(d[2:], alg)
	return outContext{ctxSigning, d}
}
