// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// Create dispositions: what to do about a file that is or is not there.
const (
	dispSupersede   uint32 = 0
	dispOpen        uint32 = 1
	dispCreate      uint32 = 2
	dispOpenIf      uint32 = 3
	dispOverwrite   uint32 = 4
	dispOverwriteIf uint32 = 5
)

// Create options this server reads.
const (
	optDirectoryFile    uint32 = 0x00000001
	optNonDirectoryFile uint32 = 0x00000040
	optDeleteOnClose    uint32 = 0x00001000
)

// Create actions, reported back so a client knows what happened.
const (
	actionSuperseded  uint32 = 0
	actionOpened      uint32 = 1
	actionCreated     uint32 = 2
	actionOverwritten uint32 = 3
)

// An openFile is one handle a client holds.
type openFile struct {
	id            [16]byte
	path          string // as the driver spells it: "/sub/file.txt"
	share         *share
	dir           bool
	deleteOnClose bool

	// f is the driver's positional handle when it has one. A driver without
	// Opener leaves this nil and the whole-file path is used instead, which is
	// O(size) per request and is why the probe exists.
	f filesystem.File
	w filesystem.WritableFile
}

// allOnesFileID is how a chained request says "the file the previous operation
// opened". macOS sends CREATE and QUERY_INFO together and puts this in the
// second one, so a server that looks it up literally finds nothing.
var allOnesFileID = [16]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

func (c *conn) fileByID(b []byte) *openFile {
	if len(b) < 16 {
		return nil
	}
	id := [16]byte(b[:16])
	if id == allOnesFileID {
		return c.files[c.lastFile]
	}
	return c.files[id]
}

// create opens or makes a file, and is where most of a mount's decisions are.
func (c *conn) create(h header, body []byte, msg []byte) ([]byte, error) {
	sh := c.tree(h)
	if sh == nil {
		return errorResponse(h, statusNetworkNameDeleted), nil
	}
	if sh.ipc {
		// There are no pipes behind IPC$ here. Saying so by name is what lets
		// a client fall back; it is asking for \srvsvc or \wkssvc, and it
		// carries on without them.
		return errorResponse(h, statusObjectNameNotFound), nil
	}
	// CREATE stats, may write, stats again and opens. Two clients creating the
	// same file would otherwise both find it missing.
	defer sh.changing()()
	if len(body) < 56 {
		return nil, fmt.Errorf("smb: CREATE body of %d bytes is too short", len(body))
	}
	disposition := binary.LittleEndian.Uint32(body[36:])
	options := binary.LittleEndian.Uint32(body[40:])
	nameOff := int(binary.LittleEndian.Uint16(body[44:]))
	nameLen := int(binary.LittleEndian.Uint16(body[46:]))
	if nameOff < 0 || nameLen < 0 || nameOff+nameLen > len(msg) {
		return nil, fmt.Errorf("smb: the file name is not inside the message")
	}
	p, ok := smbPathToFS(fromUTF16le(msg[nameOff : nameOff+nameLen]))
	if !ok {
		return errorResponse(h, statusObjectNameNotFound), nil
	}

	writing := disposition != dispOpen
	if writing && sh.ro {
		return errorResponse(h, statusMediaWriteProtected), nil
	}

	// SMB is caseless and this server says so; the driver underneath may not
	// be. See casefold.go: the name is taken as it came unless nothing is
	// there under it.
	p = resolveCase(sh.fsys, p)

	st, statErr := sh.fsys.Stat(p)
	exists := statErr == nil
	action := actionOpened

	switch {
	case exists && (disposition == dispCreate):
		return errorResponse(h, statusObjectNameCollision), nil
	case !exists && (disposition == dispOpen || disposition == dispOverwrite):
		return errorResponse(h, statusObjectNameNotFound), nil
	case !exists && (disposition == dispCreate || disposition == dispOpenIf ||
		disposition == dispOverwriteIf || disposition == dispSupersede):
		if options&optDirectoryFile != 0 {
			if err := sh.fsys.MkDir(p, 0o755); err != nil {
				return errorResponse(h, statusFor(err, statusAccessDenied)), nil
			}
		} else if err := sh.fsys.WriteFile(p, nil, 0o644); err != nil {
			return errorResponse(h, statusFor(err, statusAccessDenied)), nil
		}
		action = actionCreated
		if st, statErr = sh.fsys.Stat(p); statErr != nil {
			return errorResponse(h, statusFor(statErr, statusObjectNameNotFound)), nil
		}
	case exists && (disposition == dispOverwrite || disposition == dispOverwriteIf || disposition == dispSupersede):
		if isDir(st) {
			return errorResponse(h, statusFileIsADirectory), nil
		}
		if err := sh.fsys.WriteFile(p, nil, 0o644); err != nil {
			return errorResponse(h, statusFor(err, statusAccessDenied)), nil
		}
		action = actionOverwritten
		if disposition == dispSupersede {
			action = actionSuperseded
		}
		if st, statErr = sh.fsys.Stat(p); statErr != nil {
			return errorResponse(h, statusFor(statErr, statusObjectNameNotFound)), nil
		}
	}

	// A client says what it expects to find, and being told the truth is what
	// lets it fall back instead of failing later on a read.
	dir := isDir(st)
	if dir && options&optNonDirectoryFile != 0 {
		return errorResponse(h, statusFileIsADirectory), nil
	}
	if !dir && options&optDirectoryFile != 0 {
		return errorResponse(h, statusNotADirectory), nil
	}

	of := &openFile{path: p, share: sh, dir: dir, deleteOnClose: options&optDeleteOnClose != 0}
	if !dir {
		if o, canOpen := sh.fsys.(filesystem.Opener); canOpen {
			if f, err := o.OpenFile(p); err == nil {
				of.f = f
				// The positional write path is an upgrade OF the open file,
				// probed on the File and not on the Filesystem: a driver can
				// return a plain File for one file and a writable one for the
				// next.
				if w, canWrite := f.(filesystem.WritableFile); canWrite {
					of.w = w
				}
			}
		}
	}
	c.nextFile++
	binary.LittleEndian.PutUint64(of.id[:8], c.nextFile)
	binary.LittleEndian.PutUint64(of.id[8:], uint64(h.treeID))
	c.files[of.id] = of
	c.lastFile = of.id

	const bodyLen = 88
	b := append(responseTo(h, statusSuccess), make([]byte, bodyLen+1)...)
	rb := b[headerLen:]
	binary.LittleEndian.PutUint16(rb[0:], 89)
	binary.LittleEndian.PutUint32(rb[4:], action)
	writeTimes(rb[8:])
	size := sizeOf(st)
	binary.LittleEndian.PutUint64(rb[40:], allocationOf(size))
	binary.LittleEndian.PutUint64(rb[48:], size)
	binary.LittleEndian.PutUint32(rb[56:], attributesOf(st, sh.ro))
	copy(rb[64:], of.id[:])
	// The contexts offset stays ZERO because there are none. Pointing it at
	// the one pad byte the structure size accounts for is what a real client
	// rejects: it requires the offset to be eight-byte aligned, and 153 is
	// not. Zero is how "there are none" is spelled.
	return b, nil
}

// writeTimes fills the four timestamps a client shows. go-filesystems does not
// report any of them -- Stat is mode, size and inode -- so they are all the
// same value, and it is NOW rather than zero: a zero FILETIME is the year 1601,
// which a file manager displays as a date and a backup tool treats as ancient.
func writeTimes(b []byte) {
	t := filetime(time.Now())
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(b[i*8:], t)
	}
}

func (c *conn) closeFile(h header, body []byte) ([]byte, error) {
	if len(body) < 24 {
		return nil, fmt.Errorf("smb: CLOSE body of %d bytes is too short", len(body))
	}
	of := c.fileByID(body[8:])
	if of == nil {
		return errorResponse(h, statusFileClosed), nil
	}
	if of.f != nil {
		of.f.Close()
	}
	delete(c.files, of.id)
	defer of.share.changing()() // the file may go with the handle
	// The listing this handle was paging through goes with it. It holds a Stat
	// for every entry in the directory, and a client that opens and closes
	// directories all day -- which is what a file manager does -- would
	// otherwise leave one behind each time.
	delete(c.searches, of.id)
	if of.deleteOnClose && !of.share.ro {
		if of.dir {
			of.share.fsys.DeleteDir(of.path)
		} else {
			of.share.fsys.DeleteFile(of.path)
		}
	}

	b := append(responseTo(h, statusSuccess), make([]byte, 60)...)
	rb := b[headerLen:]
	binary.LittleEndian.PutUint16(rb[0:], 60)
	// Flags bit 0 means "the attributes below are filled in"; leaving it clear
	// says they are not, which is honest for a handle that has just gone.
	return b, nil
}

func (c *conn) read(h header, body []byte) ([]byte, error) {
	if len(body) < 48 {
		return nil, fmt.Errorf("smb: READ body of %d bytes is too short", len(body))
	}
	length := int(binary.LittleEndian.Uint32(body[4:]))
	offset := int64(binary.LittleEndian.Uint64(body[8:]))
	of := c.fileByID(body[16:])
	if of == nil {
		return errorResponse(h, statusFileClosed), nil
	}
	if of.dir {
		return errorResponse(h, statusInvalidDeviceRequest), nil
	}
	defer of.share.reading()()
	if length > maxReadSize {
		length = maxReadSize
	}
	if offset < 0 {
		return errorResponse(h, statusInvalidParameter), nil
	}

	buf := make([]byte, length)
	var n int
	if of.f != nil {
		var err error
		n, err = of.f.ReadAt(buf, offset)
		if err != nil && !errors.Is(err, io.EOF) {
			return errorResponse(h, statusFor(err, statusEndOfFile)), nil
		}
	} else {
		// No positional read: the whole file, every time. See Opener's
		// documentation for why a driver that cannot answer a byte range
		// should not pretend to.
		data, err := of.share.fsys.ReadFile(of.path)
		if err != nil {
			return errorResponse(h, statusFor(err, statusEndOfFile)), nil
		}
		if offset < int64(len(data)) {
			n = copy(buf, data[offset:])
		}
	}
	if n == 0 {
		// END_OF_FILE, not a zero-length success: a client that gets zero
		// bytes with success reads forever.
		return errorResponse(h, statusEndOfFile), nil
	}

	const bodyLen = 16
	b := append(responseTo(h, statusSuccess), make([]byte, bodyLen+n)...)
	rb := b[headerLen:]
	binary.LittleEndian.PutUint16(rb[0:], 17)
	rb[2] = headerLen + bodyLen // data offset, from the start of the message
	binary.LittleEndian.PutUint32(rb[4:], uint32(n))
	copy(rb[bodyLen:], buf[:n])
	return b, nil
}

func (c *conn) write(h header, body []byte, msg []byte) ([]byte, error) {
	if len(body) < 48 {
		return nil, fmt.Errorf("smb: WRITE body of %d bytes is too short", len(body))
	}
	dataOff := int(binary.LittleEndian.Uint16(body[2:]))
	length := int(binary.LittleEndian.Uint32(body[4:]))
	offset := int64(binary.LittleEndian.Uint64(body[8:]))
	of := c.fileByID(body[16:])
	if of == nil {
		return errorResponse(h, statusFileClosed), nil
	}
	if of.share.ro {
		return errorResponse(h, statusMediaWriteProtected), nil
	}
	if of.dir {
		return errorResponse(h, statusInvalidDeviceRequest), nil
	}
	if dataOff < 0 || length < 0 || dataOff+length > len(msg) {
		return nil, fmt.Errorf("smb: the write payload is not inside the message")
	}
	data := msg[dataOff : dataOff+length]
	defer of.share.changing()()

	if of.w != nil {
		if _, err := of.w.WriteAt(data, offset); err != nil {
			return errorResponse(h, statusFor(err, statusAccessDenied)), nil
		}
		if err := of.w.Sync(); err != nil {
			return errorResponse(h, statusFor(err, statusAccessDenied)), nil
		}
	} else {
		// Read, splice, write the whole file back. O(size) per request, which
		// a client streaming in blocks turns into O(n^2) -- the reason
		// WritableFile exists. A failure here is reported and NEVER retried
		// through another path: it has already changed the file.
		old, err := of.share.fsys.ReadFile(of.path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errorResponse(h, statusFor(err, statusAccessDenied)), nil
		}
		end := offset + int64(len(data))
		if int64(len(old)) < end {
			grown := make([]byte, end)
			copy(grown, old)
			old = grown
		}
		copy(old[offset:], data)
		if err := of.share.fsys.WriteFile(of.path, old, 0o644); err != nil {
			return errorResponse(h, statusFor(err, statusAccessDenied)), nil
		}
	}

	b := append(responseTo(h, statusSuccess), make([]byte, 16)...)
	rb := b[headerLen:]
	binary.LittleEndian.PutUint16(rb[0:], 17)
	binary.LittleEndian.PutUint32(rb[4:], uint32(length))
	return b, nil
}

// flush has nothing to do for a driver that has already written, and says so
// with success rather than with NOT_IMPLEMENTED: a client treats a failed
// flush as data loss.
func (c *conn) flush(h header, body []byte) ([]byte, error) {
	if len(body) >= 24 {
		if of := c.fileByID(body[8:]); of != nil && of.w != nil {
			defer of.share.changing()()
			if err := of.w.Sync(); err != nil {
				return errorResponse(h, statusFor(err, statusAccessDenied)), nil
			}
		}
	}
	return simpleResponse(h, statusSuccess, 4), nil
}

// statusFor maps a driver's error onto the status a client reads. The default
// is the caller's, because what "not found" means depends on what was asked.
func statusFor(err error, fallback uint32) uint32 {
	switch {
	case err == nil:
		return statusSuccess
	case errors.Is(err, os.ErrNotExist):
		return statusObjectNameNotFound
	case errors.Is(err, os.ErrExist):
		return statusObjectNameCollision
	case errors.Is(err, os.ErrPermission):
		return statusAccessDenied
	case errors.Is(err, io.EOF):
		return statusEndOfFile
	default:
		return fallback
	}
}
