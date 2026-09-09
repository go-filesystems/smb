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

**And with Windows** — the client this was written for. Windows 11 ARM64 25H2,
`New-SmbMapping`, then `dir`, `type`, a subdirectory, a write, a **rename**, a
delete, and a 512 KiB copy whose sha256 matches the host's. The client reports
what it negotiated:

```
ServerName ShareName Dialect Signed Encrypted
---------- --------- ------- ------ ---------
10.0.2.100 IPC$      3.0.2     True     False
10.0.2.100 shared    3.0.2     True     False
```

`Signed True` is why signing is implemented: Windows requires it. The per-user
lists hold there too — a reader's write comes back as "The media is write
protected", and a share `allow` does not name them as "Access is denied". See
[docs/verifying-with-windows.md](docs/verifying-with-windows.md) for the recipe
and the **two traps** that make this hard to do at all.

| | |
|---|---|
| dialect negotiation | including the 1996 greeting a modern client still opens with |
| NTLMv2 over SPNEGO | the password never leaves the server |
| opening, reading, writing | positional through `Opener`/`WritableFile`, whole-file where a driver has neither |
| listing, renaming, truncating, deleting | including the chained requests macOS sends on every open, and the ones Windows sends whose FIRST operation is meant to fail |
| signing | **HMAC-SHA256** for 2.x, **AES-CMAC** for 3.x, both implemented here |
| dialects | 2.1, 3.0 and 3.0.2 — Linux mounts with no `vers=` at all, macOS settles on 3.0.2 |
| encryption and 3.1.1 | **not yet** — 3.1.1 changes the shape of the exchange, and naming it without pre-authentication integrity would promise what is not there |
| byte-range locks | taken, released and **enforced** on reads and writes, including *waiting* for one |
| change notification | on changes that go **through this server** — one made in the image by something else is invisible, because nothing underneath tells us |
| asynchronous replies | `STATUS_PENDING` with an AsyncId, and `CANCEL` |
| per-user access | who may connect (`allow`) and who may write (`writers`), per share — a reader is told so in the access mask rather than one refusal at a time |
| share enumeration | `NetrShareEnum` over DCE/RPC on `\srvsvc`, listing what **this user** may connect to — verified against Samba's own client |
| streams, oplocks and leases | **not yet**, and each answers by name rather than by silence |

Enumeration is verified with Samba's `smbclient -L`, which is the reference
implementation of the client side. macOS cannot judge it: `smbutil view` binds
with `ncacn_np:HOST[\pipe\srvsvc]`, and a named-pipe binding has **no port
field**, so it dials 445 whatever the URL said — against a server on a high
port it logs `RPC to srvsrvc gave error 0x16c9a034`, falls back to the SMB1
`\PIPE\LANMAN` call, and prints "unable to list resources: Broken pipe". A
proxy between the two shows the tree connect to IPC$ and then nothing: the
pipe is never opened. Serving on 445 needs privilege, so that check is a
person's to run.

Windows found one defect nothing else could, and it is the reason to test
against an operating system rather than a library: **a chained request whose
predecessor failed was carried out anyway**. Windows checks that a rename's
target name is free with a compounded CREATE + CLOSE in one message, and the
CREATE is *supposed* to fail. The CLOSE that follows carries an all-ones file
id — "the file the previous operation opened" — and with no such file it
resolved to whatever the connection opened last: the source file, still held by
the client. The next `SET_INFO` came back `FILE_CLOSED` and the rename failed
with "The handle is invalid", about a handle the server had shut behind the
client's back. macOS and Linux never send a chain whose first operation fails,
and the Go client never chains at all.

What is still unchecked: this ran through a QEMU guest-forward rather than on
port 445 itself, and encryption and 3.1.1 are absent whatever the client is.

## Serving one from the command line

```sh
go run github.com/go-filesystems/smb/cmd/smb-server@latest \
    --image disk.img --user alice --password-file pw
```

```
disk.img (fat32) on \\127.0.0.1:4445\disk
  macOS:  mount_smbfs //alice@127.0.0.1:4445/disk /Volumes/disk
  Linux:  sudo mount -t cifs //127.0.0.1/disk /mnt -o port=4445,username=alice
```

The filesystem inside the image is worked out rather than declared:
[`go-filesystems/detect`](https://github.com/go-filesystems/detect) reads the
magic and hands back the driver that owns it — fat32, exfat, ext4, ntfs,
iso9660, squashfs or hfsplus, all registered the same way. The password comes from a **file**, never a flag: an argument is visible
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

share "scratch" {
  image   = "/srv/scratch.img"
  allow   = ["alice", "bob"] # only these two may connect
  writers = ["alice"]        # bob gets it read-only
}
```

```sh
smb-server --config /etc/smb.d
```

Before restarting a server people are using, `check` answers the three
questions the file alone cannot — does it parse, does every image open, and
what would be served to whom:

```
$ smb-server check /etc/smb.d
listening on 0.0.0.0:4445 as "ATTIC"

SHARE    IMAGE                FILESYSTEM  WRITE           WHO MAY CONNECT
photos   /srv/photos.img      fat32       no (read_only)  anyone who authenticates
scratch  /srv/scratch.img     ext4        alice           alice and bob

USER   PASSWORD FROM
alice  /etc/smb/alice.pw
bob    the configuration file

this configuration can be served
```

It opens every image read-only and closes it again, so it is safe to run
against a live server's images — and it never prints a password, only where
one comes from.

A share is read-write only if the image **can** be opened for writing: one on
a read-only medium, or one owned by somebody else, is served read-only and
says which shares it did that to. `os.Open` returns a handle with a `WriteAt`
method whichever way it was opened, so nothing in Go's types says no — a
mount is what said no.

A share that names nobody is every user's, read-write — so `allow` and
`writers` are what you reach for when the server has more than one person on
it. A name in either list that belongs to no `user` block is refused at
startup: `allow = ["alise"]` would otherwise lock Alice out of her own share
and start happily.

On Windows, a path in an HCL string needs its backslashes doubled — `"C:\\srv\\photos.img"` — or forward slashes, which HCL and Windows both accept. `\U` and `\a` are escape sequences, and a single-backslash path is a syntax error rather than a path.

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
