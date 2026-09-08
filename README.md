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

**The handshake works, against clients this project did not write.**

| | |
|---|---|
| dialect negotiation | including the 1996 greeting a modern client still opens with |
| NTLMv2 authentication | over SPNEGO, with the password never leaving the server |
| connecting to a share | by name, without case |
| reading and writing files | **not yet** — every other command answers `STATUS_NOT_IMPLEMENTED` by name, so a client reports instead of waiting |

Verified two ways. `go-smb2` — a client written by someone else — authenticates
and connects, in a test that runs everywhere. And macOS 26's own client, which
answered `Authentication error` before NTLM worked and now gets as far as
asking for the share list (which needs the DCE/RPC pipe this server does not
have yet).

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
