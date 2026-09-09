// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// A config is what the HCL files say. One share and one user fit on a command
// line; a machine that serves several images to several people does not, and
// that is what the files are for.
//
//	listen = "0.0.0.0:4445"
//	name   = "ATTIC"
//
//	user "alice" {
//	  password_file = "/etc/smb/alice.pw"
//	}
//
//	share "photos" {
//	  image     = "/srv/photos.img"
//	  read_only = true
//	}
//
//	share "scratch" {
//	  image   = "/srv/scratch.img"
//	  allow   = ["alice", "bob"] # only these two may connect
//	  writers = ["alice"]        # bob gets it read-only
//	}
type config struct {
	Listen string       `hcl:"listen,optional"`
	Name   string       `hcl:"name,optional"`
	Users  []userBlock  `hcl:"user,block"`
	Shares []shareBlock `hcl:"share,block"`
}

// A userBlock is a set of credentials the server will accept. The password
// comes from the file named here, or -- when it is written inline -- from the
// configuration itself, which is a choice about who may read that file.
type userBlock struct {
	Name         string `hcl:"name,label"`
	Password     string `hcl:"password,optional"`
	PasswordFile string `hcl:"password_file,optional"`
}

// A shareBlock is one image, exported under a name.
//
// Allow and Writers are who may connect and who may write. Both left out is
// the old behaviour and the common case: every user gets the share, and gets
// it read-write unless ReadOnly says otherwise.
type shareBlock struct {
	Name     string   `hcl:"name,label"`
	Image    string   `hcl:"image"`
	ReadOnly bool     `hcl:"read_only,optional"`
	Allow    []string `hcl:"allow,optional"`
	Writers  []string `hcl:"writers,optional"`
}

// loadConfig reads every file named, and every .hcl file in every directory
// named, as ONE configuration.
//
// They are merged rather than read in turn, which is what makes an
// /etc/smb.d/ of small files work: a user in one file and a share in another
// are the same configuration, and a name defined twice is an error that names
// both places rather than the last one silently winning.
func loadConfig(paths []string) (*config, error) {
	parser := hclparse.NewParser()
	var files []*hcl.File
	for _, p := range expandConfigPaths(paths) {
		f, diags := parser.ParseHCLFile(p)
		if diags.HasErrors() {
			return nil, diagError(parser, diags)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no configuration files were found in %s", strings.Join(paths, ", "))
	}

	var cfg config
	if diags := gohcl.DecodeBody(hcl.MergeFiles(files), nil, &cfg); diags.HasErrors() {
		return nil, diagError(parser, diags)
	}
	if err := cfg.check(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// expandConfigPaths turns a directory into the .hcl files inside it, in a
// stable order: two runs of the same directory must serve the same thing.
func expandConfigPaths(paths []string) []string {
	var out []string
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			matches, _ := filepath.Glob(filepath.Join(p, "*.hcl"))
			sort.Strings(matches)
			out = append(out, matches...)
			continue
		}
		out = append(out, p)
	}
	return out
}

// check refuses a configuration that would start a server nobody can use.
func (c *config) check() error {
	if len(c.Shares) == 0 {
		return fmt.Errorf("there are no shares: a server with nothing to serve is not one")
	}
	if len(c.Users) == 0 {
		// SMB has no anonymous mode worth offering, so this is a refusal
		// rather than a warning: every client would be turned away.
		return fmt.Errorf("there are no users: nobody could authenticate")
	}
	seen := map[string]string{}
	for _, s := range c.Shares {
		key := strings.ToUpper(s.Name)
		if where, taken := seen[key]; taken {
			return fmt.Errorf("two shares answer to %q (the other is %s): SMB compares names without case", s.Name, where)
		}
		seen[key] = s.Image
		if s.Image == "" {
			return fmt.Errorf("share %q has no image", s.Name)
		}
	}
	users := map[string]bool{}
	for _, u := range c.Users {
		if users[u.Name] {
			return fmt.Errorf("user %q is defined twice", u.Name)
		}
		users[u.Name] = true
		switch {
		case u.Password == "" && u.PasswordFile == "":
			return fmt.Errorf("user %q has neither a password nor a password_file", u.Name)
		case u.Password != "" && u.PasswordFile != "":
			return fmt.Errorf("user %q has both a password and a password_file: say which one", u.Name)
		}
	}
	// A name in allow or writers that belongs to nobody is a typo, and a typo
	// here is silent in the worst way: "alise" in allow locks Alice out of
	// her own share and the server starts happily. It is checked against the
	// users rather than trusted, and the message names the share.
	for _, s := range c.Shares {
		for _, who := range s.Allow {
			if !users[who] {
				return fmt.Errorf("share %q allows %q, who is not a user here", s.Name, who)
			}
		}
		for _, who := range s.Writers {
			if !users[who] {
				return fmt.Errorf("share %q lets %q write, who is not a user here", s.Name, who)
			}
			// A writer who may not connect never writes. Saying which of the
			// two lists is wrong is the reader's job, not ours.
			if len(s.Allow) > 0 && !slices.Contains(s.Allow, who) {
				return fmt.Errorf("share %q lets %q write but does not allow them to connect", s.Name, who)
			}
		}
		if s.ReadOnly && len(s.Writers) > 0 {
			return fmt.Errorf("share %q is read_only and also lists writers: read_only wins, so say one or the other", s.Name)
		}
	}
	return nil
}

// password reads what this user authenticates with.
func (u userBlock) password() (string, error) {
	if u.PasswordFile != "" {
		b, err := os.ReadFile(u.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("user %q: %w", u.Name, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return u.Password, nil
}

// diagError turns HCL's diagnostics into an error that keeps what makes them
// worth having: the file, the line, and the source snippet.
func diagError(parser *hclparse.Parser, diags hcl.Diagnostics) error {
	var sb strings.Builder
	w := hcl.NewDiagnosticTextWriter(&sb, parser.Files(), 78, false)
	if err := w.WriteDiagnostics(diags); err != nil {
		return diags
	}
	return fmt.Errorf("%s", strings.TrimSpace(sb.String()))
}
