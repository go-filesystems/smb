// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The command line, through cobra.
//
// One command grew three: serving is what it does, `check` is what a person
// wants before restarting a server other people are using, and `version` is
// what a bug report needs. Cobra brings `help` and `completion` with it.
//
// The flags now take TWO dashes -- --image, not -image -- because that is
// pflag's grammar and a single dash there is read as a cluster of short flags.
// A person who types the old form gets told so by name rather than left with
// "unknown shorthand flag: 'i' in -image".

// options is what the flags say. It is one struct because the root command and
// `serve` are the same command under two names, and they must see the same
// flags.
type options struct {
	files    []string
	image    string
	share    string
	addr     string
	user     string
	pwFile   string
	readOnly bool
	name     string
}

func (o *options) bind(f *pflag.FlagSet) {
	f.StringArrayVarP(&o.files, "config", "c", nil,
		"an HCL file, or a directory of .hcl files, describing shares and users (repeatable)")
	f.StringVarP(&o.image, "image", "i", "", "a disk image to export")
	f.StringVarP(&o.share, "share", "s", "",
		"the name to export it under (default: the image's file name without its extension)")
	f.StringVarP(&o.addr, "addr", "a", "127.0.0.1:4445", "the address to listen on")
	f.StringVarP(&o.user, "user", "u", "", "the user a client authenticates as")
	f.StringVarP(&o.pwFile, "password-file", "p", "", "a file holding that user's password")
	f.BoolVar(&o.readOnly, "read-only", false, "refuse every write, whatever the image would allow")
	f.StringVar(&o.name, "name", "GOFS", "what the server calls itself to a client")
}

const longHelp = `smb-server exports disk images over SMB, so they can be mounted by the file
manager of macOS, Linux or Windows with nothing installed on the client.

One image:

    smb-server --image disk.img --user alice --password-file pw

Several, with users and per-share access, from HCL:

    smb-server --config /etc/smb.d

    listen = "0.0.0.0:4445"

    user "alice" {
      password_file = "/etc/smb/alice.pw"
    }

    share "photos" {
      image     = "/srv/photos.img"
      read_only = true
    }

The filesystem inside an image is worked out rather than declared: the magic
says which driver owns it. The password comes from a FILE, never a flag: an
argument is visible in the process list to every user on the machine.`

func newRootCmd() *cobra.Command {
	var o options
	root := &cobra.Command{
		Use:   "smb-server",
		Short: "Export disk images over SMB",
		Long:  longHelp,
		Args:  noArgs,
		// The error is printed once, by main, in this command's own voice.
		// Usage on a failure that is not about the command line buries the
		// reason under forty lines of flags.
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd, &o)
		},
	}
	o.bind(root.PersistentFlags())
	// Cobra fills this in at 2 while it is looking for a command; noArgs asks
	// for suggestions AFTER that, on a command it already found, so it would
	// be comparing against zero and never suggest anything.
	root.SuggestionsMinimumDistance = 2
	root.SetFlagErrorFunc(flagError)
	root.AddCommand(newServeCmd(&o), newCheckCmd(&o))
	return root
}

// newServeCmd is the root command under its own name. `smb-server --config x`
// and `smb-server serve --config x` are the same thing: the first is what a
// person types, the second is what reads well in a service file.
func newServeCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:           "serve",
		Short:         "Serve the shares and wait for clients",
		Args:          noArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd, o)
		},
	}
}

// noArgs refuses a leftover argument, and says what one usually means.
//
// There are two ways to get one, and a person cannot tell them apart from
// "unknown command": a mistyped subcommand, and a stale command line.
// `-config /etc/smb.d` does not fail -- pflag reads -c as the shorthand for
// --config and "onfig" as its value, which leaves the path over -- so the
// message a stale line meets is this one and not the one below.
//
// A suggestion is offered when the argument looks like a command somebody
// meant to type; the dashes are explained when it looks like a path, and both
// when it could be either.
func noArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	arg := args[0]
	dashes := "flags take two dashes here -- --config, not -config -- and a single dash is\n" +
		"read as a short flag, which leaves the rest over. `smb-server --help` lists them"

	if strings.ContainsAny(arg, `/\.`) {
		return fmt.Errorf("unexpected argument %q\n\n%s", arg, dashes)
	}
	if near := cmd.Root().SuggestionsFor(arg); len(near) > 0 {
		return fmt.Errorf("unknown command %q\n\nDid you mean this?\n\t%s", arg, strings.Join(near, "\n\t"))
	}
	return fmt.Errorf("unknown command %q\n\nIf you meant a flag: %s", arg, dashes)
}

// flagError says what a single dash means to pflag.
//
// This command took `-config` for as long as it used the standard library's
// flag package, and everything written down about it -- READMEs, service
// files, a person's shell history -- says so. pflag reads a single dash as a
// cluster of one-letter flags, so `-config` is c, o, n, f, i and g: the error
// it produces names a flag nobody typed.
func flagError(cmd *cobra.Command, err error) error {
	msg := err.Error()
	if i := strings.Index(msg, "unknown shorthand flag: "); i >= 0 {
		if j := strings.Index(msg, " in -"); j >= 0 {
			typed := msg[j+len(" in -"):]
			if len(typed) > 1 {
				return fmt.Errorf("%s\n\nflags take two dashes here: --%s, not -%s", msg, typed, typed)
			}
		}
	}
	return err
}

// version is what the build says it is, which for `go install ...@latest` is a
// real version and for a build from a work tree is "(devel)".
func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "unknown"
}
