// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"time"
)

// What a hostile server is not allowed to make the client do.
const (
	clDirBuf = 1 << 20
	// clMaxIdleBatches is how many QUERY_DIRECTORY answers in a row may add
	// nothing to a listing (a batch of "." and ".." only) before the server is
	// taken to be stalling the walk instead of ending it.
	clMaxIdleBatches = 16
)

// clMaxDirEntries is the number of entries one directory listing may return; a
// variable so a test can lower it.
var clMaxDirEntries = 1 << 22

var errClientEmptyBatch = errors.New("smb: the server answered QUERY_DIRECTORY with success and no entry")

func (s *ClientShare) rt(ctx context.Context, cmd command, charge uint16, b []byte, op string) (clResult, error) {
	r, err := s.c.roundTrip(ctx, cmd, s.tid, charge, b, nil, false)
	if err != nil {
		return r, err
	}
	if r.h.status != statusSuccess {
		return r, &StatusError{op, r.h.status}
	}
	return r, nil
}

func (s *ClientShare) open(ctx context.Context, p string, access, attrs, disp, opts uint32) (clCreated, error) {
	name, err := clPath(p)
	if err != nil {
		return clCreated{}, err
	}
	r, err := s.rt(ctx, cmdCreate, 1, clCreateRequest(name, access, attrs, disp, opts), "CREATE")
	if err != nil {
		return clCreated{}, err
	}
	return parseCreateResp(r.msg)
}

func (s *ClientShare) closeID(ctx context.Context, id [16]byte) error {
	_, err := s.rt(ctx, cmdClose, 1, clCloseRequest(id), "CLOSE")
	return err
}

// ClientInfo is what Stat knows.
type ClientInfo struct {
	Name    string
	Size    int64
	Attrs   uint32
	ModTime time.Time
}

func (i ClientInfo) IsDir() bool { return i.Attrs&attrDirectory != 0 }

// Stat opens p for its attributes only (a reparse point is not followed) and
// closes it.
func (s *ClientShare) Stat(ctx context.Context, p string) (ClientInfo, error) {
	cr, err := s.open(ctx, p, accReadAttributes|accSynchronize, 0, uint32(dispOpen), optOpenReparse)
	if err != nil {
		return ClientInfo{}, err
	}
	if err := s.closeID(ctx, cr.id); err != nil {
		return ClientInfo{}, err
	}
	return ClientInfo{Name: p, Size: int64(min(cr.eof, 1<<62)), Attrs: cr.attrs, ModTime: fileTime(cr.mtime)}, nil
}

// ReadDir lists a directory: QUERY_DIRECTORY until STATUS_NO_MORE_FILES, "." and
// ".." left out.
func (s *ClientShare) ReadDir(ctx context.Context, p string) ([]ClientDirEntry, error) {
	cr, err := s.open(ctx, p, accListDirectory|accReadAttributes|accSynchronize, 0, uint32(dispOpen), optDirectory)
	if err != nil {
		return nil, err
	}
	defer s.closeID(context.WithoutCancel(ctx), cr.id)
	out := min(clDirBuf, s.c.maxTrans)
	var all []ClientDirEntry
	idle := 0
	for restart := true; ; restart = false {
		r, err := s.c.roundTrip(ctx, cmdQueryDirectory, s.tid, creditCharge(int(out)), clQueryDirRequest(cr.id, restart, out), nil, false)
		if err != nil {
			return nil, err
		}
		if r.h.status == statusNoMoreFiles {
			return all, nil
		}
		if r.h.status != statusSuccess {
			return nil, &StatusError{"QUERY_DIRECTORY", r.h.status}
		}
		b, err := parseInfoResp(r.msg)
		if err != nil {
			return nil, err
		}
		es, err := parseDirEntries(b)
		if err != nil {
			return nil, err
		}
		before := len(all)
		for _, e := range es {
			if e.Name == "." || e.Name == ".." {
				continue
			}
			if len(all) >= clMaxDirEntries {
				return nil, errors.New("smb: the directory listing is longer than the client accepts")
			}
			all = append(all, e)
		}
		if len(all) > before {
			idle = 0
		} else if idle++; idle > clMaxIdleBatches {
			return nil, errClientEmptyBatch
		}
	}
}

// ClientFsInfo is the share's capacity.
type ClientFsInfo struct {
	Unit, Total, Free, Avail uint64 // bytes per allocation unit, then units
}

// Statfs reads FileFsFullSizeInformation through the share's root.
func (s *ClientShare) Statfs(ctx context.Context) (ClientFsInfo, error) {
	cr, err := s.open(ctx, "", accReadAttributes|accSynchronize, 0, uint32(dispOpen), optDirectory)
	if err != nil {
		return ClientFsInfo{}, err
	}
	defer s.closeID(context.WithoutCancel(ctx), cr.id)
	r, err := s.rt(ctx, cmdQueryInfo, 1, clQueryInfoRequest(infoTypeFilesystem, fsFullSizeInfo, 4096, cr.id), "QUERY_INFO")
	if err != nil {
		return ClientFsInfo{}, err
	}
	b, err := parseInfoResp(r.msg)
	if err != nil {
		return ClientFsInfo{}, err
	}
	f, err := parseFullSize(b)
	if err != nil {
		return ClientFsInfo{}, err
	}
	return ClientFsInfo{f.unit, f.total, f.free, f.avail}, nil
}

// ClientFile is an open file, read-only.
type ClientFile struct {
	s    *ClientShare
	id   [16]byte
	size int64
	off  int64
	ctx  context.Context
}

// Open opens p for reading. ctx bounds every read made through the file.
func (s *ClientShare) Open(ctx context.Context, p string) (*ClientFile, error) {
	cr, err := s.open(ctx, p, accReadData|accReadAttributes|accSynchronize, 0, uint32(dispOpen), optNonDirectory)
	if err != nil {
		return nil, err
	}
	return &ClientFile{s: s, id: cr.id, size: int64(min(cr.eof, 1<<62)), ctx: ctx}, nil
}

// Size is the length the server reported at open.
func (f *ClientFile) Size() int64 { return f.size }

// ReadAt fills p from offset off, one READ per negotiated chunk. A READ may
// never return more than was asked: that is a server writing past our buffer.
func (f *ClientFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	n := 0
	for n < len(p) {
		want := uint32(min(len(p)-n, int(f.s.c.maxRead)))
		r, err := f.s.rt(f.ctx, cmdRead, creditCharge(int(want)), clReadRequest(f.id, uint64(off)+uint64(n), want), "READ")
		if err != nil {
			var se *StatusError
			if errors.As(err, &se) && se.Status == statusEndOfFile {
				return n, io.EOF
			}
			return n, err
		}
		data, err := parseReadResp(r.msg, want)
		if err != nil {
			return n, err
		}
		if len(data) == 0 {
			return n, io.EOF
		}
		n += copy(p[n:], data)
	}
	return n, nil
}

func (f *ClientFile) Read(p []byte) (int, error) {
	n, err := f.ReadAt(p, f.off)
	f.off += int64(n)
	if n > 0 && err == io.EOF {
		err = nil
	}
	return n, err
}

// Close releases the handle.
func (f *ClientFile) Close() error { return f.s.closeID(context.WithoutCancel(f.ctx), f.id) }

// WriteFile creates or truncates p and writes data to it.
func (s *ClientShare) WriteFile(ctx context.Context, p string, data []byte) error {
	cr, err := s.open(ctx, p, accWriteData|accReadAttributes|accSynchronize, 0x80, uint32(dispOverwriteIf), optNonDirectory)
	if err != nil {
		return err
	}
	defer s.closeID(context.WithoutCancel(ctx), cr.id)
	for off := 0; off < len(data); {
		n := min(len(data)-off, int(s.c.maxWrite))
		r, err := s.rt(ctx, cmdWrite, creditCharge(n), clWriteRequest(cr.id, uint64(off), data[off:off+n]), "WRITE")
		if err != nil {
			return err
		}
		w, err := parseWriteResp(r.msg)
		if err != nil {
			return err
		}
		if w == 0 || int(w) > n {
			return errors.New("smb: the server wrote an impossible number of bytes")
		}
		off += int(w)
	}
	return nil
}

// Remove deletes a file or an empty directory: it opens with DELETE and
// delete-on-close, and the close does the deletion.
func (s *ClientShare) Remove(ctx context.Context, p string) error {
	cr, err := s.open(ctx, p, accDelete|accReadAttributes|accSynchronize, 0, uint32(dispOpen), uint32(optDeleteOnClose)|optOpenReparse)
	if err != nil {
		return err
	}
	return s.closeID(ctx, cr.id)
}
