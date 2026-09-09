// SPDX-License-Identifier: BSD-3-Clause

// Command smb-server exports a disk image over SMB, so it can be mounted by the
// file manager of macOS, Linux or Windows with nothing installed on the client.
//
//	smb-server -image disk.img -user alice -password-file pw
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
		fmt.Fprintln(os.Stderr, "smb-server:", err)
		os.Exit(1)
	}
}

// configFiles collects repeated -config flags.
type configFiles []string

func (c *configFiles) String() string     { return strings.Join(*c, ", ") }
func (c *configFiles) Set(v string) error { *c = append(*c, v); return nil }

func run() error {
	var (
		files    configFiles
		image    = flag.String("image", "", "a disk image to export")
		share    = flag.String("share", "", `the name to export it under (default: the image's file name without its extension)`)
		addr     = flag.String("addr", "127.0.0.1:4445", "the address to listen on")
		user     = flag.String("user", "", "the user a client authenticates as")
		pwFile   = flag.String("password-file", "", "a file holding that user's password")
		readOnly = flag.Bool("read-only", false, "refuse every write, whatever the image would allow")
		name     = flag.String("name", "GOFS", "what the server calls itself to a client")
	)
	flag.Var(&files, "config", "an HCL file, or a directory of .hcl files, describing shares and users (repeatable)")
	flag.Usage = usage
	flag.Parse()

	cfg, err := configure(files, *image, *share, *user, *pwFile, *addr, *name, *readOnly)
	if err != nil {
		return err
	}

	srv := smb.New()
	srv.SetName(cfg.Name)
	for _, u := range cfg.Users {
		pw, err := u.password()
		if err != nil {
			return err
		}
		srv.AddUser(u.Name, pw)
	}

	// Every image is opened before the listener, so a bad path is a refusal
	// at the start rather than an error the first client sees.
	var opened []filesystem.Filesystem
	defer func() {
		for _, fsys := range opened {
			fsys.Close()
		}
	}()
	type served struct {
		name string
		kind detect.Type
		path string
	}
	var shares []served
	for _, s := range cfg.Shares {
		fsys, kind, err := openImage(s.Image)
		if err != nil {
			return fmt.Errorf("opening %s: %w", s.Image, err)
		}
		opened = append(opened, fsys)
		var opts []smb.ShareOption
		if s.ReadOnly {
			opts = append(opts, smb.ReadOnly())
		}
		if err := srv.Share(s.Name, fsys, opts...); err != nil {
			return err
		}
		shares = append(shares, served{s.Name, kind, s.Image})
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	// Say the address the listener actually got, not the one asked for: with
	// :0 they are different, and the one that matters is what a client dials.
	who := cfg.Users[0].Name
	for _, s := range shares {
		fmt.Printf("%s (%s) on \\\\%s\\%s\n", s.path, s.kind, ln.Addr(), s.name)
		fmt.Printf("  macOS:  mount_smbfs //%s@%s/%s /Volumes/%s\n", who, ln.Addr(), s.name, s.name)
		fmt.Printf("  Linux:  sudo mount -t cifs //%s/%s /mnt -o port=%s,username=%s\n",
			host(ln.Addr().String()), s.name, port(ln.Addr().String()), who)
	}

	// A signal closes the server, which closes the listener and drops every
	// connection -- and, more to the point, lets the deferred Close above run
	// so each driver flushes whatever it was holding.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		srv.Close()
	}()
	return srv.Serve(ln)
}

// configure turns whichever way the person asked -- files, flags, or files
// with a couple of flags -- into one configuration.
//
// The flags are the shape of the one-image case, and they stay: a person
// serving a single image should not have to write a file to do it. When files
// ARE given they own the shares and the users, because a share defined in two
// places is a question nobody wants to answer at three in the morning.
func configure(files []string, image, share, user, pwFile, addr, name string, readOnly bool) (*config, error) {
	if len(files) > 0 {
		if image != "" || user != "" || pwFile != "" {
			return nil, fmt.Errorf("-config describes the shares and the users; -image, -user and -password-file do not go with it")
		}
		cfg, err := loadConfig(files)
		if err != nil {
			return nil, err
		}
		// The two flags that are about the server rather than about what it
		// serves fill in what the files left out.
		if cfg.Listen == "" {
			cfg.Listen = addr
		}
		if cfg.Name == "" {
			cfg.Name = name
		}
		return cfg, nil
	}

	if image == "" || user == "" || pwFile == "" {
		usage()
		return nil, fmt.Errorf("either -config, or all three of -image, -user and -password-file")
	}
	if share == "" {
		share = defaultShareName(image)
	}
	return &config{
		Listen: addr,
		Name:   name,
		Users:  []userBlock{{Name: user, PasswordFile: pwFile}},
		Shares: []shareBlock{{Name: share, Image: image, ReadOnly: readOnly}},
	}, nil
}

func usage() {
	fmt.Fprint(flag.CommandLine.Output(), `smb-server exports disk images over SMB.

One image:

    smb-server -image disk.img -user alice -password-file pw

Several, from HCL:

    smb-server -config /etc/smb.d

    listen = "0.0.0.0:4445"

    user "alice" {
      password_file = "/etc/smb/alice.pw"
    }

    share "photos" {
      image     = "/srv/photos.img"
      read_only = true
    }

`)
	flag.PrintDefaults()
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
