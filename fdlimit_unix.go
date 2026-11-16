// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package smb

import "syscall"

// fdLimit is the soft limit on open file descriptors, and whether it is known.
func fdLimit() (uint64, bool) {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil {
		return 0, false
	}
	return uint64(r.Cur), true
}
