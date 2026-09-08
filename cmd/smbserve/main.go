// SPDX-License-Identifier: BSD-3-Clause

// Command smbserve exports a disk image over SMB, so it can be mounted by the
// file manager of macOS, Linux or Windows with nothing installed on the client.
//
//	smbserve -image disk.img -user alice -password-file pw
//	mount_smbfs //alice@127.0.0.1:4445/disk /Volumes/disk           # macOS
//	mount -t cifs //127.0.0.1/disk /mnt -o port=4445,username=alice  # Linux
//
// The filesystem inside the image is worked out rather than declared:
// go-filesystems/detect reads the magic and hands back the driver that owns
// it.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/go-filesystems/detect"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/smb"

	filesystem_exfat "github.com/go-filesystems/exfat"
	filesystem_ext4 "github.com/go-filesystems/ext4"
	filesystem_fat32 "github.com/go-filesystems/fat32"
	"github.com/go-filesystems/hfsplus"
	filesystem_iso9660 "github.com/go-filesystems/iso9660"
	filesystem_ntfs "github.com/go-filesystems/ntfs"
	filesystem_squashfs "github.com/go-filesystems/squashfs"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "smbserve:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		image    = flag.String("image", "", "the disk image to export (required)")
		share    = flag.String("share", "", `the name to export it under (default: the image's file name without its extension)`)
		addr     = flag.String("addr", "127.0.0.1:4445", "the address to listen on")
		user     = flag.String("user", "", "the user a client authenticates as (required)")
		pwFile   = flag.String("password-file", "", "a file holding that user's password (required)")
		readOnly = flag.Bool("read-only", false, "refuse every write, whatever the image would allow")
		name     = flag.String("name", "GOFS", "what the server calls itself to a client")
	)
	flag.Parse()
	if *image == "" || *user == "" || *pwFile == "" {
		flag.Usage()
		return fmt.Errorf("an image, a user and a password file are all required")
	}
	// The password comes from a FILE, never a flag value: an argument is
	// visible in the process list to every user on the machine, and lands in
	// a shell's history besides.
	pw, err := os.ReadFile(*pwFile)
	if err != nil {
		return fmt.Errorf("reading the password: %w", err)
	}

	fsys, kind, err := openImage(*image)
	if err != nil {
		return fmt.Errorf("opening %s: %w", *image, err)
	}
	defer fsys.Close()

	shareName := *share
	if shareName == "" {
		shareName = defaultShareName(*image)
	}
	srv := smb.New()
	srv.SetName(*name)
	srv.AddUser(*user, strings.TrimRight(string(pw), "\r\n"))
	opts := []smb.ShareOption{}
	if *readOnly {
		opts = append(opts, smb.ReadOnly())
	}
	if err := srv.Share(shareName, fsys, opts...); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	// Say the address the listener actually got, not the one asked for: with
	// :0 they are different, and the one that matters is what a client dials.
	fmt.Printf("%s (%s) on \\\\%s\\%s\n", *image, kind, ln.Addr(), shareName)
	fmt.Printf("  macOS:  mount_smbfs //%s@%s/%s /Volumes/%s\n", *user, ln.Addr(), shareName, shareName)
	fmt.Printf("  Linux:  sudo mount -t cifs //%s/%s /mnt -o port=%s,username=%s\n",
		host(ln.Addr().String()), shareName, port(ln.Addr().String()), *user)

	// A signal closes the server, which closes the listener and drops every
	// connection -- and, more to the point, lets the deferred Close above run
	// so the driver flushes whatever it was holding.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		srv.Close()
	}()
	if err := srv.Serve(ln); err != nil {
		return err
	}
	return nil
}

// openImage works out what is inside the image and hands back the driver that
// owns it.
//
// detect reads the magic; the dispatch below is written out rather than
// registered, because the drivers do not share one entry point: fat32, exfat
// and ext4 open a PATH (and a partition index), while iso9660, squashfs and
// hfsplus open a reader and a size. detect.Register only fits the second kind,
// so a registration table here would silently cover half the list.
func openImage(path string) (filesystem.Filesystem, detect.Type, error) {
	probe, err := os.Open(path)
	if err != nil {
		return nil, detect.Unknown, err
	}
	info, err := probe.Stat()
	if err != nil {
		probe.Close()
		return nil, detect.Unknown, err
	}
	kind, err := detect.Detect(probe, info.Size())
	probe.Close()
	if err != nil {
		return nil, detect.Unknown, err
	}

	// -1 is the whole image: no partition table to look through.
	const wholeImage = -1
	switch kind {
	case detect.FAT32:
		fsys, err := filesystem_fat32.Open(path, wholeImage)
		return fsys, kind, err
	case detect.ExFAT:
		fsys, err := filesystem_exfat.Open(path, wholeImage)
		return fsys, kind, err
	case detect.Ext4:
		fsys, err := filesystem_ext4.Open(path, wholeImage)
		return fsys, kind, err
	case detect.NTFS:
		fsys, err := filesystem_ntfs.Open(path, wholeImage)
		return fsys, kind, err
	case detect.ISO9660, detect.SquashFS, detect.HFSPlus:
		// These read through a handle that has to outlive this function, so
		// it is closed by closing the filesystem rather than here.
		f, err := os.Open(path)
		if err != nil {
			return nil, kind, err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, kind, err
		}
		var fsys filesystem.Filesystem
		switch kind {
		case detect.ISO9660:
			fsys, err = filesystem_iso9660.Open(f, info.Size())
		case detect.SquashFS:
			fsys, err = filesystem_squashfs.Open(f, info.Size())
		case detect.HFSPlus:
			fsys, err = hfsplus.Open(f, info.Size())
		}
		if err != nil {
			f.Close()
			return nil, kind, err
		}
		return closeWith{fsys, f}, kind, nil
	default:
		return nil, kind, fmt.Errorf("this command cannot open a %s image", kind)
	}
}

// closeWith closes the file the driver was reading through, after the driver
// itself.
type closeWith struct {
	filesystem.Filesystem
	f *os.File
}

func (c closeWith) Close() error {
	err := c.Filesystem.Close()
	if cerr := c.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// defaultShareName is the image's file name without its extension, which is
// what a person would have typed.
func defaultShareName(path string) string {
	base := path
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.LastIndex(base, "."); i > 0 {
		base = base[:i]
	}
	if base == "" {
		return "disk"
	}
	return base
}

func host(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func port(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return p
}
