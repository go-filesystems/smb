// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// check is the command a person wants before restarting a server other people
// are using.
//
// It answers three questions the configuration alone cannot: does it parse,
// does every image OPEN, and what would actually be served to whom. The last
// one is the point -- `allow` and `writers` are easy to get subtly wrong, and
// the failure is silent: the server starts, and somebody cannot see their own
// share.
//
// It opens every image read-only and closes it again. Opening is what catches
// a wrong path, an image with a partition table, or a filesystem no driver
// here owns -- and doing it read-only means running this against a live
// server's images cannot disturb them.
func newCheckCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "check [file or directory...]",
		Short: "Read the configuration, open every image, and say what would be served",
		Long: `check parses the configuration, opens every image read-only to see that it
is really there and that a driver owns it, and prints what would be served to
whom. It changes nothing and serves nothing.

The paths are the same as --config takes, and may be given either way.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			files := append(append([]string{}, o.files...), args...)
			if len(files) == 0 {
				// The flag form is checked too, so a person can check what
				// they are about to serve with the same words they serve it.
				if o.image == "" {
					return fmt.Errorf("nothing to check: name a configuration file, a directory of them, or --image")
				}
			}
			checked := *o
			checked.files = files
			cfg, err := configure(&checked)
			if err != nil {
				return err
			}
			return report(cmd, cfg)
		},
	}
}

// report prints what would be served. It is a table because the questions are
// comparisons -- who may write which share -- and a column answers those in
// one look.
func report(cmd *cobra.Command, cfg *config) error {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "listening on %s as %q\n\n", cfg.Listen, cfg.Name)

	registerDrivers()
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SHARE\tIMAGE\tFILESYSTEM\tWRITE\tWHO MAY CONNECT")
	var failed error
	for _, s := range cfg.Shares {
		kindOf, writable := "unreadable", "no"
		fsys, kind, _, err := openImage(s.Image, true)
		if err != nil {
			// Named and carried on: a person fixing several paths wants all
			// of them at once, not one per run.
			failed = fmt.Errorf("at least one image could not be opened")
			kindOf = fmt.Sprintf("cannot open: %v", err)
		} else {
			kindOf = string(kind)
			fsys.Close()
			// Whether it will take a write is a question about the FILE, not
			// about the configuration: an image nobody may write to is served
			// read-only however the block reads. Asked without the read-only
			// flag, so the answer is the file's own.
			if f, fileRO, ferr := openImageFile(s.Image, false); ferr == nil {
				f.Close()
				if !fileRO && !s.ReadOnly {
					writable = "yes"
				}
			}
		}
		who := "anyone who authenticates"
		if len(s.Allow) > 0 {
			who = join(s.Allow)
		}
		write := writable
		switch {
		case s.ReadOnly:
			write = "no (read_only)"
		case len(s.Writers) > 0 && writable == "yes":
			write = join(s.Writers)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Name, s.Image, kindOf, write, who)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(out)
	fmt.Fprintln(w, "USER\tPASSWORD FROM")
	for _, u := range cfg.Users {
		from := "the configuration file"
		if u.PasswordFile != "" {
			// The file is named; what is IN it is never printed, here or
			// anywhere else.
			from = u.PasswordFile
			if _, err := u.password(); err != nil {
				from = fmt.Sprintf("%s (cannot read it: %v)", u.PasswordFile, err)
				failed = fmt.Errorf("at least one password could not be read")
			}
		}
		fmt.Fprintf(w, "%s\t%s\n", u.Name, from)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if failed != nil {
		return failed
	}
	fmt.Fprintln(out, "\nthis configuration can be served")
	return nil
}

// join is a list a person reads, not a slice a program prints.
func join(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	out := names[0]
	for _, n := range names[1 : len(names)-1] {
		out += ", " + n
	}
	return out + " and " + names[len(names)-1]
}
