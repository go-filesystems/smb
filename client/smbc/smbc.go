// Package smbc is the smbc command: ls, df, du and check against an SMB share.
// cmd/smbc is a four-line main around RootCmd.
//
// Credentials come from exactly two places: --credentials-file (mount.cifs
// format, mode 0600 or stricter, owned by the caller) or --credential NAME
// ($CREDENTIALS_DIRECTORY/NAME, systemd LoadCredentialEncrypted). There is no
// flag and no environment variable that carries a password.
package smbc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"time"

	"github.com/go-filesystems/smb/client"
	"github.com/spf13/cobra"
)

// Exit codes. 0 is success; each failure class of `check` has its own.
const (
	ExitFailure     = 1  // any other failure
	ExitUsage       = 2  // bad arguments or credentials
	ExitConnect     = 10 // TCP or negotiate
	ExitAuth        = 11 // session setup refused
	ExitTree        = 12 // tree connect refused
	ExitRead        = 13 // read probe
	ExitWrite       = 14 // write probe (create, verify or delete)
	ExitIncomplete  = 3  // a walk hit a bound or an unreadable directory
	defaultJobs     = 8
	defaultTimeout  = 30 * time.Second
	flagCredFile    = "credentials-file"
	flagCredSystemd = "credential"
)

// ExitError carries the process exit code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// osExit is replaceable by tests.
var osExit = os.Exit

// Main runs the command line and exits.
func Main() {
	root := RootCmd()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	root.SetContext(ctx)
	err := root.Execute()
	if err == nil {
		return
	}
	var ee *ExitError
	code := ExitFailure
	if errors.As(err, &ee) {
		code = ee.Code
	}
	fmt.Fprintln(root.ErrOrStderr(), "smbc:", err)
	osExit(code)
}

type common struct {
	credFile, cred string
	timeout        time.Duration
	allowPlain     bool
}

func (c *common) options() (client.Options, error) {
	if (c.credFile == "") == (c.cred == "") {
		return client.Options{}, &ExitError{ExitUsage, fmt.Errorf("give exactly one of --%s and --%s", flagCredFile, flagCredSystemd)}
	}
	var cr client.Credentials
	var err error
	if c.credFile != "" {
		cr, err = client.LoadCredentialsFile(c.credFile)
	} else {
		cr, err = client.LoadSystemdCredential(c.cred)
	}
	if err != nil {
		return client.Options{}, &ExitError{ExitUsage, err}
	}
	return client.Options{Auth: client.NTLM{Credentials: cr}, ConnectTimeout: c.timeout, AllowUnencrypted: c.allowPlain}, nil
}

// open parses the name, dials and mounts.
func (c *common) open(cmd *cobra.Command, name string) (client.Target, *client.Session, *client.Share, error) {
	t, err := client.ParseUNC(name)
	if err != nil {
		return t, nil, nil, &ExitError{ExitUsage, err}
	}
	o, err := c.options()
	if err != nil {
		return t, nil, nil, err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if c.allowPlain {
		fmt.Fprintln(cmd.ErrOrStderr(), "smbc: warning: --allow-unencrypted: SMB encryption is not required, the data may cross the network in the clear (signed only)")
	}
	s, err := client.Dial(ctx, t, o)
	if err != nil {
		return t, nil, nil, stepExit(err)
	}
	sh, err := s.Mount(t.Share)
	if err != nil {
		s.Close()
		return t, nil, nil, stepExit(err)
	}
	return t, s, sh.WithContext(ctx), nil
}

func stepExit(err error) error {
	var se *client.StepError
	if errors.As(err, &se) {
		return &ExitError{exitFor(se.Step), err}
	}
	return &ExitError{ExitFailure, err}
}

func exitFor(s client.Step) int {
	switch s {
	case client.StepConnect:
		return ExitConnect
	case client.StepAuth:
		return ExitAuth
	case client.StepTree:
		return ExitTree
	case client.StepRead:
		return ExitRead
	case client.StepWriteCreate, client.StepWriteVerify, client.StepWriteDelete:
		return ExitWrite
	}
	return ExitFailure
}

// RootCmd builds the smbc command tree.
func RootCmd() *cobra.Command {
	c := &common{}
	root := &cobra.Command{
		Use:           "smbc",
		Short:         "SMB2/3 client: ls, df, du, check",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `smbc talks SMB 2/3 (NTLMv2, signing required, SMB 3.1.1 preferred, encryption
required: every request is sent encrypted, and a server that cannot encrypt is
refused unless --allow-unencrypted is given, which warns).

Credentials: --credentials-file PATH (mount.cifs format: username=, password=,
domain=; mode 0600 or stricter, owned by you) or --credential NAME (reads
$CREDENTIALS_DIRECTORY/NAME, set by systemd LoadCredentialEncrypted=). There
is no flag or environment variable that carries a password.`,
	}
	pf := root.PersistentFlags()
	pf.StringVar(&c.credFile, flagCredFile, "", "credentials file (mount.cifs format, mode 0600)")
	pf.StringVar(&c.cred, flagCredSystemd, "", "systemd credential name, read from $CREDENTIALS_DIRECTORY")
	pf.DurationVar(&c.timeout, "connect-timeout", defaultTimeout, "bound on connect, negotiate and authenticate")
	pf.BoolVar(&c.allowPlain, "allow-unencrypted", false, "do not require SMB encryption (signed only); warns")
	root.AddCommand(lsCmd(c), dfCmd(c), duCmd(c), checkCmd(c))
	return root
}

func lsCmd(c *common) *cobra.Command {
	return &cobra.Command{
		Use:   "ls //host[:port]/share[/path]",
		Short: "list a directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, s, sh, err := c.open(cmd, args[0])
			if err != nil {
				return err
			}
			defer s.Close()
			defer sh.Close()
			ents, err := sh.ReadDir(t.Path)
			if err != nil {
				return &ExitError{ExitFailure, err}
			}
			sort.Slice(ents, func(i, j int) bool { return ents[i].Name < ents[j].Name })
			out := cmd.OutOrStdout()
			for _, e := range ents {
				kind, name := "-", e.Name
				switch {
				case e.Symlink:
					kind = "l"
				case e.Dir:
					kind, name = "d", name+"/"
				}
				fmt.Fprintf(out, "%s %12d %s %s\n", kind, e.Size, e.ModTime.UTC().Format("2006-01-02 15:04"), name)
			}
			return nil
		},
	}
}

func dfCmd(c *common) *cobra.Command {
	var human bool
	cmd := &cobra.Command{
		Use:   "df //host[:port]/share",
		Short: "total and free space (FileFsFullSizeInformation)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, s, sh, err := c.open(cmd, args[0])
			if err != nil {
				return err
			}
			defer s.Close()
			defer sh.Close()
			fi, err := sh.Statfs(t.Path)
			if err != nil {
				return &ExitError{ExitFailure, err}
			}
			out := cmd.OutOrStdout()
			unit := "bytes"
			if human {
				unit = "human"
			}
			used := fi.Total - min(fi.Free, fi.Total)
			pct := 0.0
			if fi.Total > 0 {
				pct = 100 * float64(used) / float64(fi.Total)
			}
			fmt.Fprintf(out, "%-24s %14s %14s %14s %14s %5s\n", "Share ("+unit+")", "Size", "Used", "Free", "Avail", "Use%")
			fmt.Fprintf(out, "%-24s %14s %14s %14s %14s %4.0f%%\n", "//"+t.Host+"/"+t.Share,
				size(fi.Total, human), size(used, human), size(fi.Free, human), size(fi.Avail, human), pct)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&human, "human-readable", "H", false, "print sizes as 1.5G instead of bytes")
	return cmd
}

func duCmd(c *common) *cobra.Command {
	var human, summarize bool
	var jobs int
	cmd := &cobra.Command{
		Use:   "du //host[:port]/share[/path]",
		Short: "disk usage of a tree (apparent size)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, s, sh, err := c.open(cmd, args[0])
			if err != nil {
				return err
			}
			defer s.Close()
			defer sh.Close()
			out, errw := cmd.OutOrStdout(), cmd.ErrOrStderr()
			var unreadable int
			o := client.DuOptions{Jobs: jobs, OnError: func(p string, err error) {
				unreadable++
				fmt.Fprintf(errw, "smbc: %s: %v\n", "/"+p, err)
			}}
			if !summarize {
				o.Visit = func(e client.DuEntry) { fmt.Fprintf(out, "%s\t/%s\n", size(uint64(e.Bytes), human), e.Path) }
			}
			total, err := sh.Du(cmd.Context(), t.Path, o)
			if err != nil {
				return &ExitError{ExitIncomplete, err}
			}
			if summarize {
				fmt.Fprintf(out, "%s\t/%s\n", size(uint64(total), human), t.Path)
			}
			if unreadable > 0 {
				return &ExitError{ExitIncomplete, fmt.Errorf("%d directories could not be read; the total is a lower bound", unreadable)}
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&human, "human-readable", "H", false, "print sizes as 1.5G instead of bytes")
	cmd.Flags().BoolVarP(&summarize, "summarize", "s", false, "print only the total")
	cmd.Flags().IntVar(&jobs, "jobs", defaultJobs, "directories listed concurrently")
	return cmd
}

func checkCmd(c *common) *cobra.Command {
	return &cobra.Command{
		Use:   "check //host[:port]/share[/dir]",
		Short: "connect, tree connect, read probe, write probe; names the failing step",
		Long: `check connects, authenticates, tree-connects, lists the directory (read probe),
then creates a temporary file in it, reads it back and deletes it (write probe).
It prints one line per step and a verdict. Exit status: 0 all good; 10 connect;
11 auth; 12 tree connect; 13 read probe; 14 write probe; 2 bad usage.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := client.ParseUNC(args[0])
			if err != nil {
				return &ExitError{ExitUsage, err}
			}
			o, err := c.options()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			rep := client.Check(ctx, t, o)
			out := cmd.OutOrStdout()
			for _, s := range rep.Steps {
				switch {
				case s.Skipped:
					fmt.Fprintf(out, "%-13s skipped\n", s.Step)
				case s.OK:
					fmt.Fprintf(out, "%-13s ok\n", s.Step)
				default:
					fmt.Fprintf(out, "%-13s FAILED: %v\n", s.Step, s.Err)
				}
			}
			fmt.Fprintln(out, rep.Verdict())
			if st, _ := rep.Failed(); st != "" {
				return &ExitError{exitFor(st), errors.New("check failed at " + string(st))}
			}
			return nil
		},
	}
}

// size formats n as bytes or, with human, as K/M/G/T/P (powers of 1024, one decimal).
func size(n uint64, human bool) string {
	if !human {
		return fmt.Sprintf("%d", n)
	}
	const units = "KMGTPE"
	if n < 1024 {
		return fmt.Sprintf("%dB", n)
	}
	f := float64(n)
	i := -1
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f%c", f, units[i])
}
