// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package smb

import (
	"errors"
	"syscall"
)

// acceptRetryable says whether a failure of accept(2) is one that will pass:
// what the error itself calls temporary, and the errnos a listener meets in real
// life that Go does not -- EMFILE and ENFILE (out of descriptors, which a flood
// causes and the end of the flood cures) and ECONNABORTED and ECONNRESET (the
// peer left before the connection was accepted).
func acceptRetryable(err error) bool {
	if t, ok := err.(interface{ Temporary() bool }); ok && t.Temporary() {
		return true
	}
	for _, e := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED, syscall.ECONNRESET} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
