// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package smb

// fdLimit: where there is no descriptor limit to read, there is none to respect.
func fdLimit() (uint64, bool) { return 0, false }
