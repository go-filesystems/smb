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

**A share mounts, and you can work in it.**

Verified with the macOS kernel client on macOS 26 — `mount_smbfs`, then `ls`,
`cat`, a write, and a 512 KiB copy whose sha256 matches — over a FAT32 image
served by [`go-filesystems/fat32`](https://github.com/go-filesystems/fat32).
`smbutil statshares` reports `SMB_3.0.2` and `SIGNING_SUPPORTED TRUE`.

And with the Linux kernel client in CI, which mounts it with **no dialect
named**:

```
//127.0.0.1/disk on /mnt type cifs (rw,vers=default,username=alice,…)
```

| | |
|---|---|
| dialect negotiation | including the 1996 greeting a modern client still opens with |
| NTLMv2 over SPNEGO | the password never leaves the server |
| opening, reading, writing | positional through `Opener`/`WritableFile`, whole-file where a driver has neither |
| listing, renaming, truncating, deleting | including the chained requests macOS sends on every open |
| signing | **HMAC-SHA256** for 2.x, **AES-CMAC** for 3.x, both implemented here |
| dialects | 2.1, 3.0 and 3.0.2 — Linux mounts with no `vers=` at all, macOS settles on 3.0.2 |
| encryption and 3.1.1 | **not yet** — 3.1.1 changes the shape of the exchange, and naming it without pre-authentication integrity would promise what is not there |
| locks, change notification, streams, share enumeration | **not yet**, and each answers by name rather than by silence |

Windows is the client this package was written for and the one **not yet
verified**: signing is implemented because Windows 11 requires it, and
`FSCTL_VALIDATE_NEGOTIATE_INFO` because it drops a connection whose answer to
it is missing — but neither has been put to a real Windows client here. Two
operating systems have mounted this; the third is a claim nobody has checked.

## Serving one from the command line

```sh
go run github.com/go-filesystems/smb/cmd/smb-server@latest \
    -image disk.img -user alice -password-file pw
```

```
disk.img (fat32) on \\127.0.0.1:4445\disk
  macOS:  mount_smbfs //alice@127.0.0.1:4445/disk /Volumes/disk
  Linux:  sudo mount -t cifs //127.0.0.1/disk /mnt -o port=4445,username=alice
```

The filesystem inside the image is worked out rather than declared:
[`go-filesystems/detect`](https://github.com/go-filesystems/detect) reads the
magic. The password comes from a **file**, never a flag: an argument is visible
in the process list to every user on the machine.

Several images, several people, from HCL — one file or a directory of them:

```hcl
listen = "0.0.0.0:4445"
name   = "ATTIC"

user "alice" {
  password_file = "/etc/smb/alice.pw"
}

share "photos" {
  image     = "/srv/photos.img"
  read_only = true
}
```

```sh
smb-server -config /etc/smb.d
```

The files in a directory are **merged**, so a user in one and a share in
another are the same configuration — and a name defined twice is an error that
names both places rather than the last one silently winning. A mistake is
reported the way HCL reports one, with the file, the line and the source.

## Serving one from Go

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
