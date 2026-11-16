// SPDX-License-Identifier: BSD-3-Clause

package smb

import "crypto/sha512"

// Pre-authentication integrity, the part of 3.1.1 that makes the dialect
// exchange tamper-evident without a second round trip.
//
// [MS-SMB2] 3.3.5.4 ("Receiving an SMB2 NEGOTIATE Request") starts a hash chain
// at zero and folds into it, with the hash the client chose (SHA-512 is the only
// one defined, 2.2.3.1.1), the NEGOTIATE request and the NEGOTIATE response
// exactly as they were on the wire. 3.3.5.5.3 ("Handling GSS-API
// Authentication") continues the chain for each session: every SESSION_SETUP
// request and every response that is not the last. The final value is the
// CONTEXT of the signing key's derivation (see signingKeyFor), so a client and a
// server that were shown different negotiate messages derive different keys and
// the first signed message fails.
//
// It is also why the bytes hashed must be the bytes sent: a response is hashed
// after it is built and not touched again.

// preauthHashSize is the output of SHA-512, which is also the size of the
// chain's initial value.
const preauthHashSize = sha512.Size

// The HashAlgorithms ids of SMB2_PREAUTH_INTEGRITY_CAPABILITIES.
const hashIDSHA512 uint16 = 0x0001

// preauthStart is the value a chain begins with: "initialize with zero".
func preauthStart() []byte { return make([]byte, preauthHashSize) }

// preauthExtend is H(prev || msg), the one step of the chain.
func preauthExtend(prev, msg []byte) []byte {
	h := sha512.New()
	h.Write(prev)
	h.Write(msg)
	return h.Sum(nil)
}
