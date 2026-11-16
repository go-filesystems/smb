// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// AES-CCM (RFC 3610), which the standard library does not have and SMB 3 needs:
// AES-128-CCM is the one cipher every 3.x server and client speaks, and the only
// one 3.0 and 3.0.2 have ([MS-SMB2] 2.2.41, 3.1.4.3).
//
// SMB uses a 16-byte tag and an 11-byte nonce, so the length field L of RFC 3610
// is 15 - 11 = 4 bytes. The construction here takes both as parameters, because
// the RFC's own test vectors use other sizes and a function that can only be
// run with SMB's would only be checked against itself.

type ccm struct {
	b     cipher.Block
	nonce int
	tag   int
}

// newCCM returns an AEAD with the given nonce and tag sizes. RFC 3610: the tag
// is 4, 6, 8, 10, 12, 14 or 16 bytes, and the nonce 7 to 13.
func newCCM(b cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if b.BlockSize() != 16 {
		return nil, errors.New("smb: CCM needs a 128-bit block cipher")
	}
	if tagSize < 4 || tagSize > 16 || tagSize%2 != 0 {
		return nil, errors.New("smb: CCM tag size must be 4, 6, ..., 16")
	}
	if nonceSize < 7 || nonceSize > 13 {
		return nil, errors.New("smb: CCM nonce size must be 7 to 13")
	}
	return &ccm{b, nonceSize, tagSize}, nil
}

func (c *ccm) NonceSize() int { return c.nonce }
func (c *ccm) Overhead() int  { return c.tag }

// l is the size of the length field, which is whatever the nonce leaves of the
// 15 bytes of the counter block.
func (c *ccm) l() int { return 15 - c.nonce }

// maxLen is the longest message the length field can hold.
func (c *ccm) maxLen() uint64 { return 1<<(8*uint(c.l())) - 1 }

// mac is the CBC-MAC of RFC 3610 section 2.2 over B_0, the encoded additional
// data and the message, encrypted by the first keystream block as 2.3 says.
func (c *ccm) mac(nonce, aad, msg []byte) []byte {
	var x [16]byte
	step := func(blk []byte) {
		for i := range x {
			x[i] ^= blk[i]
		}
		c.b.Encrypt(x[:], x[:])
	}
	// B_0: flags, nonce, message length.
	var b0 [16]byte
	flags := byte(c.l()-1) | byte((c.tag-2)/2)<<3
	if len(aad) > 0 {
		flags |= 0x40
	}
	b0[0] = flags
	copy(b0[1:], nonce)
	for i, n := 0, uint64(len(msg)); i < c.l(); i, n = i+1, n>>8 {
		b0[15-i] = byte(n)
	}
	step(b0[:])

	pad := func(data []byte) {
		for len(data) > 0 {
			var blk [16]byte
			n := copy(blk[:], data)
			data = data[n:]
			step(blk[:])
		}
	}
	if len(aad) > 0 {
		var enc []byte
		switch a := len(aad); {
		case a < 0xFF00:
			enc = []byte{byte(a >> 8), byte(a)}
		default:
			enc = []byte{0xFF, 0xFE, byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)}
		}
		pad(append(enc, aad...))
	}
	pad(msg)
	return x[:c.tag]
}

// ctr XORs data with the keystream A_1, A_2, ... of RFC 3610 section 2.3, and
// returns the first keystream block A_0 encrypted, which masks the tag.
func (c *ccm) ctr(nonce, dst, src []byte) []byte {
	var a, s [16]byte
	a[0] = byte(c.l() - 1)
	copy(a[1:], nonce)
	counter := func(i uint64) {
		for j := 0; j < c.l(); j++ {
			a[15-j] = byte(i >> (8 * uint(j)))
		}
	}
	counter(0)
	var s0 [16]byte
	c.b.Encrypt(s0[:], a[:])
	for i := uint64(1); len(src) > 0; i++ {
		counter(i)
		c.b.Encrypt(s[:], a[:])
		n := min(16, len(src))
		for j := 0; j < n; j++ {
			dst[j] = src[j] ^ s[j]
		}
		dst, src = dst[n:], src[n:]
	}
	return s0[:]
}

func (c *ccm) Seal(dst, nonce, plaintext, aad []byte) []byte {
	if len(nonce) != c.nonce {
		panic("smb: CCM nonce of the wrong length")
	}
	if uint64(len(plaintext)) > c.maxLen() {
		panic("smb: CCM message too long")
	}
	tag := c.mac(nonce, aad, plaintext)
	out := make([]byte, len(plaintext)+c.tag)
	s0 := c.ctr(nonce, out[:len(plaintext)], plaintext)
	for i := range tag {
		out[len(plaintext)+i] = tag[i] ^ s0[i]
	}
	return append(dst, out...)
}

var errCCMOpen = errors.New("smb: CCM message authentication failed")

func (c *ccm) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != c.nonce {
		return nil, errCCMOpen
	}
	if len(ciphertext) < c.tag {
		return nil, errCCMOpen
	}
	body, got := ciphertext[:len(ciphertext)-c.tag], ciphertext[len(ciphertext)-c.tag:]
	if uint64(len(body)) > c.maxLen() {
		return nil, errCCMOpen
	}
	plain := make([]byte, len(body))
	s0 := c.ctr(nonce, plain, body)
	want := c.mac(nonce, aad, plain)
	for i := range want {
		want[i] ^= s0[i]
	}
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return nil, errCCMOpen
	}
	return append(dst, plain...), nil
}
