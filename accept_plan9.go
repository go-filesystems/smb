// SPDX-License-Identifier: BSD-3-Clause

//go:build plan9

package smb

// acceptRetryable on Plan 9 has only what the error says about itself.
func acceptRetryable(err error) bool {
	t, ok := err.(interface{ Temporary() bool })
	return ok && t.Temporary()
}
