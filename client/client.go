// Package client is an SMB2/3 client for the shares this module serves and for
// any other SMB server: connect, authenticate (pluggable), mount a share, list,
// size, walk and probe it.
//
// The protocol engine is github.com/cloudsoda/go-smb2 (already this module's
// test dependency, and the client the server is tested against); this package
// adds what a tool needs on top of it: a name parser that refuses traversal,
// credential loading from a mode-checked file or a systemd credential (never
// from a flag or an environment variable), signing required, a bounded walk,
// and a connect / tree / read / write probe that names the step that failed.
// SMB 3.1.1 is negotiated first; the session is encrypted when the server
// asks for it (session or share flag).
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
)

// Step names the stage of a connection a failure happened in.
type Step string

const (
	StepConnect     Step = "connect"      // TCP, negotiate
	StepAuth        Step = "auth"         // session setup
	StepTree        Step = "tree"         // tree connect
	StepRead        Step = "read"         // read probe
	StepWriteCreate Step = "write-create" // create the probe file
	StepWriteVerify Step = "write-verify" // read the probe file back
	StepWriteDelete Step = "write-delete" // delete the probe file
)

// StepError is a failure tagged with the step it happened in.
type StepError struct {
	Step Step
	Err  error
}

func (e *StepError) Error() string { return string(e.Step) + ": " + e.Err.Error() }
func (e *StepError) Unwrap() error { return e.Err }

// Authenticator makes the GSS initiator for one session. NTLMv2 is the one
// implementation today; Kerberos plugs in here without a change elsewhere.
type Authenticator interface {
	// Initiator is called once per session. host is the server's name, for
	// authenticators that build a service name from it (cifs/host).
	Initiator(host string) (Initiator, error)
}

// Initiator is the GSS security context an Authenticator returns.
type Initiator = smb2.Initiator

// NTLM is NTLMv2 password authentication.
type NTLM struct{ Credentials Credentials }

// Initiator implements Authenticator.
func (n NTLM) Initiator(host string) (Initiator, error) {
	if n.Credentials.User == "" {
		return nil, errors.New("no user name")
	}
	return &smb2.NTLMInitiator{
		User:      n.Credentials.User,
		Password:  n.Credentials.Password,
		Domain:    n.Credentials.Domain,
		TargetSPN: "cifs/" + host,
	}, nil
}

// Options configure Dial. Auth is required: there is no anonymous mode.
type Options struct {
	Auth Authenticator
	// DialContext opens the transport; the default is a TCP dial. Tests and
	// other transports (QUIC) substitute their own.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// ConnectTimeout bounds the dial, negotiate and session setup (default 30s,
	// negative = none). Later requests are bound by the context given to Dial.
	ConnectTimeout time.Duration
	// Limits bounds what a server can make this client hold. Zero fields take
	// the defaults.
	Limits Limits
}

// Limits are the bounds applied to anything a server names.
type Limits struct {
	MaxDirEntries int   // entries read from one directory (default 1<<20)
	MaxWalkNodes  int64 // entries visited by one walk (default 1<<26)
	MaxDepth      int   // directory depth of a walk (default 128)
	MaxProbeRead  int64 // bytes read back by the write probe (default 1 MiB)
}

func (l Limits) withDefaults() Limits {
	if l.MaxDirEntries <= 0 {
		l.MaxDirEntries = 1 << 20
	}
	if l.MaxWalkNodes <= 0 {
		l.MaxWalkNodes = 1 << 26
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = 128
	}
	if l.MaxProbeRead <= 0 {
		l.MaxProbeRead = 1 << 20
	}
	return l
}

// Session is an authenticated connection to a server.
type Session struct {
	s      *smb2.Session
	limits Limits
}

// Dial connects to t, negotiates (signing REQUIRED, SMB 3.1.1 offered first)
// and authenticates. A failure is a *StepError: StepConnect before the
// server's answer to session setup, StepAuth for the server's refusal of it.
func Dial(ctx context.Context, t Target, o Options) (*Session, error) {
	if o.Auth == nil {
		return nil, &StepError{StepAuth, errors.New("no authenticator")}
	}
	dial := o.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	init, err := o.Auth.Initiator(t.Host)
	if err != nil {
		return nil, &StepError{StepAuth, err}
	}
	parent := ctx
	ct := o.ConnectTimeout
	if ct == 0 {
		ct = 30 * time.Second
	}
	if ct > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ct)
		defer cancel()
	}
	conn, err := dial(ctx, "tcp", t.Addr())
	if err != nil {
		return nil, &StepError{StepConnect, err}
	}
	d := &smb2.Dialer{
		Negotiator: smb2.Negotiator{RequireMessageSigning: true},
		Initiator:  init,
	}
	s, err := d.DialConn(ctx, conn, t.Addr())
	if err != nil {
		conn.Close()
		var re *smb2.ResponseError
		if errors.As(err, &re) {
			return nil, &StepError{StepAuth, err}
		}
		return nil, &StepError{StepConnect, err}
	}
	return &Session{s: s.WithContext(parent), limits: o.Limits.withDefaults()}, nil
}

// Close logs off.
func (s *Session) Close() error { return s.s.Logoff() }

// Share is a mounted share (a tree connect).
type Share struct {
	sh     *smb2.Share
	limits Limits
}

// Mount tree-connects share.
func (s *Session) Mount(share string) (*Share, error) {
	sh, err := s.s.Mount(share)
	if err != nil {
		return nil, &StepError{StepTree, err}
	}
	return &Share{sh: sh, limits: s.limits}, nil
}

// Close unmounts.
func (sh *Share) Close() error { return sh.sh.Umount() }

// WithContext binds every later call to ctx.
func (sh *Share) WithContext(ctx context.Context) *Share {
	c := *sh
	c.sh = sh.sh.WithContext(ctx)
	return &c
}

// Entry is one directory entry.
type Entry struct {
	Name    string
	Size    int64
	Dir     bool
	Symlink bool
	ModTime time.Time
}

// ErrTooMany is returned when a directory or a walk exceeds its bound.
var ErrTooMany = errors.New("more entries than the limit allows")

// validName refuses what a server must not be able to make us join into a
// path: separators, traversal, NUL.
func validName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, "/\\\x00")
}

// ReadDir lists a directory, at most Limits.MaxDirEntries entries; entries with
// an unsafe name (separator, "..") are dropped, as a server must not be able to
// steer a walk out of the directory.
func (sh *Share) ReadDir(path string) ([]Entry, error) {
	f, err := sh.sh.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readEntries(f, path, sh.limits.MaxDirEntries)
}

type dirReader interface {
	Readdir(n int) ([]os.FileInfo, error)
}

// readEntries drains d. It stops at io.EOF, at an empty batch (a server that
// answers success with nothing must not make this loop for ever) and at max
// entries.
func readEntries(d dirReader, path string, max int) ([]Entry, error) {
	var out []Entry
	for {
		fis, err := d.Readdir(512)
		for _, fi := range fis {
			if !validName(fi.Name()) {
				continue
			}
			if len(out) >= max {
				return out, fmt.Errorf("%s: %w (%d)", path, ErrTooMany, max)
			}
			size := fi.Size()
			if size < 0 {
				size = 0
			}
			out = append(out, Entry{
				Name: fi.Name(), Size: size, Dir: fi.IsDir(),
				Symlink: fi.Mode()&os.ModeSymlink != 0, ModTime: fi.ModTime(),
			})
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
		if len(fis) == 0 {
			return out, nil
		}
	}
}

// FSInfo is the volume size, in bytes (MS-FSCC 2.5.4 FileFsFullSizeInformation).
type FSInfo struct {
	Total uint64 // total size
	Free  uint64 // free, ignoring quota ("actual available")
	Avail uint64 // free for the calling user (quota applied)
}

// ErrBadFSInfo is returned when the server's sizes cannot be a real volume.
var ErrBadFSInfo = errors.New("the server returned inconsistent volume sizes")

// Statfs asks the server for the volume size of path. The unit counts are
// multiplied by the allocation unit; a product that overflows, a zero unit, a
// unit above 1 GiB or counts that read as negative (the wire field is signed)
// are refused rather than reported.
func (sh *Share) Statfs(path string) (FSInfo, error) {
	fi, err := sh.sh.Statfs(path)
	if err != nil {
		return FSInfo{}, err
	}
	return fsInfoOf(fi.BlockSize(), fi.TotalBlockCount(), fi.FreeBlockCount(), fi.AvailableBlockCount())
}

func fsInfoOf(unit, total, free, avail uint64) (FSInfo, error) {
	const maxUnit = 1 << 30
	if unit == 0 || unit > maxUnit {
		return FSInfo{}, fmt.Errorf("%w: allocation unit %d", ErrBadFSInfo, unit)
	}
	limit := uint64(1<<63-1) / unit
	if total > limit || free > limit || avail > limit {
		return FSInfo{}, fmt.Errorf("%w: unit counts overflow", ErrBadFSInfo)
	}
	return FSInfo{Total: total * unit, Free: free * unit, Avail: avail * unit}, nil
}
