// SPDX-License-Identifier: BSD-3-Clause

// Package smb implements an SMB2 server that exports any
// [github.com/go-filesystems/interface.Filesystem], in pure Go with
// CGO_ENABLED=0 and no dependency outside the standard library.
//
// It is the sibling of go-filesystems/nfs, /webdav and /sftp, and the one they
// cannot replace: SMB is what Windows speaks natively — its NFS client is an
// optional feature and its WebDAV redirector is fragile — and it is what the
// macOS Finder speaks best.
//
// # Why the package is not called cifs
//
// `mount -t cifs` is what a Linux user types, and this is the server it
// connects to. But CIFS names SMB 1, which Windows removes by default and
// which this server will not speak. Exactly one SMB1 frame is answered here:
// the legacy greeting, whose answer is "let us speak SMB2".
//
// That is not a reading of the specification, it is what the client on the
// desk did. macOS 26 opens with an SMB1 NEGOTIATE offering "NT LM 0.12",
// "SMB 2.002" and "SMB 2.???"; told to use SMB2, it offers 0x0202, 0x0210,
// 0x0300, 0x0302 and 0x0311, and nothing older.
//
// # What is implemented
//
// Dialect 2.1, NTLMv2 authentication over SPNEGO, and the file operations a
// file manager performs. The dialects above it add signing algorithms,
// encryption and pre-authentication integrity; they are a later tranche, and
// what is here refuses rather than pretends.
package smb
