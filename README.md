# smb

A pure-Go **SMB2** server that exports any
[`go-filesystems`](https://github.com/go-filesystems) `Filesystem`, so a disk
image can be mounted by the file manager of Windows, macOS or Linux with
nothing installed on the client side.

Sibling of [`nfs`](https://github.com/go-filesystems/nfs),
[`webdav`](https://github.com/go-filesystems/webdav) and
[`sftp`](https://github.com/go-filesystems/sftp), and the one those three
cannot replace: SMB is what Windows speaks natively, and what macOS's Finder
speaks best.

## Why not "cifs"

`mount -t cifs` is what a Linux user types, and this is the server it connects
to — but CIFS names SMB **1**, which Windows removes by default and which this
server will not speak. The one SMB1 frame it answers is the legacy greeting,
and the answer is "let us speak SMB2".

Measured on macOS 26's client: it opens with an SMB1 `NEGOTIATE` offering
`NT LM 0.12`, `SMB 2.002` and `SMB 2.???`, and once told to use SMB2 it offers
dialects `0x0202`, `0x0210`, `0x0300`, `0x0302` and `0x0311` — no CIFS in
sight.

## Status

**A share mounts, and you can work in it.** Verified with the macOS kernel
client on macOS 26 — `mount_smbfs`, then `ls`, `cat`, a write, and a 512 KiB
copy whose sha256 matches — over a FAT32 image served by
[`go-filesystems/fat32`](https://github.com/go-filesystems/fat32).

| | |
|---|---|
| dialect negotiation | including the 1996 greeting a modern client still opens with |
| NTLMv2 over SPNEGO | the password never leaves the server |
| opening, reading, writing | positional through `Opener`/`WritableFile`, whole-file where a driver has neither |
| listing, renaming, truncating, deleting | including the chained requests macOS sends on every open |
| signing, encryption, 3.x dialects | **not yet** — so a Linux client needs `vers=2.1` |
| locks, change notification, streams, share enumeration | **not yet**, and each answers by name rather than by silence |

## Serving one

```go
fs, err := fat32.Open("disk.img", -1)
if err != nil {
	return err
}
defer fs.Close()

srv := smb.New()
srv.AddUser("alice", "hunter2")
if err := srv.Share("disk", fs); err != nil {
	return err
}
return srv.ListenAndServe("127.0.0.1:4445")
```

Port 445 is the one a client dials without being told, and it needs privilege
on every operating system — so the examples use a high port, and the mount
command names it.

## Licence

BSD-3-Clause.
