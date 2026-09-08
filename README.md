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

Early. See the package documentation for what is implemented.

## Licence

BSD-3-Clause.
