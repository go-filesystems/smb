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
// Dialects 2.1, 3.0 and 3.0.2; NTLMv2 authentication over SPNEGO or raw, as
// the client prefers; signing, with HMAC-SHA256 or AES-CMAC as the dialect
// requires; and the file operations a file manager performs: opening,
// reading, writing, listing, renaming, truncating and deleting.
//
// That is enough for `mount -t cifs` on Linux -- with no vers= at all -- and
// for mount_smbfs on macOS, which settles on 3.0.2 signed.
//
// 3.1.1 is not here. It adds pre-authentication integrity and negotiate
// contexts, which change the shape of the exchange itself; naming it without
// them would promise what is not there. Nor is encryption.
//
// Not here: byte-range locks, change notification, alternate data streams,
// security descriptors, and the DCE/RPC pipe that answers "what shares are
// there" (so a client must be told the share name rather than browsing for
// it). Each of those answers by name rather than by silence.
//
// # Serving one
//
//	fs, err := fat32.Open("disk.img", -1)
//	if err != nil {
//		return err
//	}
//	defer fs.Close()
//
//	srv := smb.New()
//	srv.AddUser("alice", "hunter2")
//	if err := srv.Share("disk", fs); err != nil {
//		return err
//	}
//	return srv.ListenAndServe("127.0.0.1:4445")
//
// Port 445 is the one a client dials without being told, and it needs
// privilege on every operating system -- so the examples use a high port, and
// the mount command names it:
//
//	mount_smbfs //alice@127.0.0.1:4445/disk /Volumes/disk          # macOS
//	mount -t cifs //127.0.0.1/disk /mnt -o port=4445,vers=2.1,...   # Linux
package smb
