// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"
	"unicode/utf16"
)

// The wire code of the in-house CLIENT engine ([MS-SMB2] 3.2, 2.2). Every
// decoder here takes the bytes a server sent and nothing else, returns a value
// or an error and never panics, so each one is fuzzed (cl_fuzz_test.go): the
// server on the other end is the party this code does not trust.
//
// Offsets in a response are from the start of the SMB2 header, so the decoders
// take the whole message, header included.

var (
	errShort    = errors.New("smb: response shorter than its structure")
	errBadField = errors.New("smb: a response field points outside the message")
)

// StatusError is a non-success NTSTATUS a server answered a command with.
type StatusError struct {
	Command string
	Status  uint32
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("smb: %s: %s (%#08x)", e.Command, statusName(e.Status), e.Status)
}

// Is maps the statuses a caller tests for onto the os errors, so
// errors.Is(err, os.ErrNotExist) works as for a local file.
func (e *StatusError) Is(target error) bool {
	switch target {
	case os.ErrNotExist:
		return e.Status == statusNoSuchFile || e.Status == statusObjectNameNotFound || e.Status == statusObjectPathNotFound
	case os.ErrPermission:
		return e.Status == statusAccessDenied
	case os.ErrExist:
		return e.Status == statusObjectNameCollision
	}
	return false
}

func statusName(s uint32) string {
	switch s {
	case statusLogonFailure:
		return "STATUS_LOGON_FAILURE"
	case statusAccessDenied:
		return "STATUS_ACCESS_DENIED"
	case statusObjectNameNotFound:
		return "STATUS_OBJECT_NAME_NOT_FOUND"
	case statusObjectPathNotFound:
		return "STATUS_OBJECT_PATH_NOT_FOUND"
	case statusBadNetworkName:
		return "STATUS_BAD_NETWORK_NAME"
	case statusNotADirectory:
		return "STATUS_NOT_A_DIRECTORY"
	case statusNoMoreFiles:
		return "STATUS_NO_MORE_FILES"
	case statusEndOfFile:
		return "STATUS_END_OF_FILE"
	case statusSharingViolation:
		return "STATUS_SHARING_VIOLATION"
	case statusUserSessionDeleted:
		return "STATUS_USER_SESSION_DELETED"
	case statusNoSuchFile:
		return "STATUS_NO_SUCH_FILE"
	}
	return "NTSTATUS"
}

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

// body is the part of a message after the 64-byte header, checked to be at
// least n bytes and to open with the structure size the command defines.
func body(msg []byte, n int, structSize uint16) ([]byte, error) {
	if len(msg) < headerLen+n {
		return nil, errShort
	}
	b := msg[headerLen:]
	if le16(b) != structSize {
		return nil, fmt.Errorf("smb: response structure size %d, want %d", le16(b), structSize)
	}
	return b, nil
}

// buf returns msg[off:off+n] when it lies after the fixed part of the response
// (min is the first byte the variable part may use) and inside the message.
func buf(msg []byte, off, n, min int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	if off < min || n < 0 || off > len(msg) || n > len(msg)-off {
		return nil, errBadField
	}
	return msg[off : off+n : off+n], nil
}

func utf16leBytes(s string) []byte { return utf16le(s) }

// ─── NEGOTIATE ───────────────────────────────────────────────────────────────

type clNegotiated struct {
	secMode   uint16
	dialect   uint16
	ctxCount  int
	ctxOff    int
	caps      uint32
	maxTrans  uint32
	maxRead   uint32
	maxWrite  uint32
	secBuffer []byte
}

func parseNegotiateResp(msg []byte) (clNegotiated, error) {
	var n clNegotiated
	b, err := body(msg, 64, 65)
	if err != nil {
		return n, err
	}
	n.secMode = le16(b[2:])
	n.dialect = le16(b[4:])
	n.ctxCount = int(le16(b[6:]))
	n.caps = le32(b[24:])
	n.maxTrans, n.maxRead, n.maxWrite = le32(b[28:]), le32(b[32:]), le32(b[36:])
	n.ctxOff = int(le32(b[60:]))
	n.secBuffer, err = buf(msg, int(le16(b[56:])), int(le16(b[58:])), headerLen+64)
	return n, err
}

// clServerContexts is what a 3.1.1 server chose.
type clServerContexts struct {
	hash      uint16
	cipher    uint16
	hasCipher bool
	signing   uint16
	hasSign   bool
}

// parseServerContexts reads the NegotiateContextList of a response: exactly one
// PREAUTH_INTEGRITY context naming one hash, at most one ENCRYPTION and one
// SIGNING context each naming ONE algorithm ([MS-SMB2] 2.2.4, 3.2.5.2).
func parseServerContexts(msg []byte, off, count int) (clServerContexts, error) {
	var c clServerContexts
	if count <= 0 || count > maxNegotiateContexts || off < headerLen+64 || off%8 != 0 || off > len(msg) {
		return c, errBadField
	}
	var preauth, enc, sign int
	for i := 0; i < count; i++ {
		if off+8 > len(msg) {
			return c, errBadField
		}
		typ, dlen := le16(msg[off:]), int(le16(msg[off+2:]))
		if off+8+dlen > len(msg) {
			return c, errBadField
		}
		d := msg[off+8 : off+8+dlen]
		switch typ {
		case ctxPreauthIntegrity:
			preauth++
			if len(d) < 6 || le16(d) != 1 || 6+int(le16(d[2:])) > len(d) {
				return c, errBadField
			}
			c.hash = le16(d[4:])
		case ctxEncryption:
			enc++
			if len(d) < 4 || le16(d) != 1 {
				return c, errBadField
			}
			c.hasCipher, c.cipher = true, le16(d[2:])
		case ctxSigning:
			sign++
			if len(d) < 4 || le16(d) != 1 {
				return c, errBadField
			}
			c.hasSign, c.signing = true, le16(d[2:])
		}
		off = (off + 8 + dlen + 7) &^ 7
	}
	if preauth != 1 || enc > 1 || sign > 1 {
		return c, errors.New("smb: the server's negotiate contexts break [MS-SMB2] 2.2.4")
	}
	return c, nil
}

// clNegotiateRequest builds the body of a NEGOTIATE request. The contexts start
// at the first 8-byte boundary after the dialects.
func clNegotiateRequest(dialects []uint16, secMode uint16, caps uint32, guid [16]byte, ctxs []byte, nctx int) []byte {
	b := make([]byte, 36)
	binary.LittleEndian.PutUint16(b[0:], 36)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(b[4:], secMode)
	binary.LittleEndian.PutUint32(b[8:], caps)
	copy(b[12:], guid[:])
	for _, d := range dialects {
		b = binary.LittleEndian.AppendUint16(b, d)
	}
	if nctx > 0 {
		for (headerLen+len(b))%8 != 0 {
			b = append(b, 0)
		}
		binary.LittleEndian.PutUint32(b[28:], uint32(headerLen+len(b)))
		binary.LittleEndian.PutUint16(b[32:], uint16(nctx))
		b = append(b, ctxs...)
	}
	return b
}

// clContexts builds the contexts a client offers: SHA-512 with a random salt,
// the ciphers it accepts and the signing algorithms, in preference order.
func clContexts(salt []byte, ciphers, signs []uint16) (out []byte, n int) {
	ctx := func(typ uint16, data []byte) {
		for len(out)%8 != 0 {
			out = append(out, 0)
		}
		out = binary.LittleEndian.AppendUint16(out, typ)
		out = binary.LittleEndian.AppendUint16(out, uint16(len(data)))
		out = append(out, 0, 0, 0, 0)
		out = append(out, data...)
		n++
	}
	d := binary.LittleEndian.AppendUint16(nil, 1)
	d = binary.LittleEndian.AppendUint16(d, uint16(len(salt)))
	d = binary.LittleEndian.AppendUint16(d, hashIDSHA512)
	ctx(ctxPreauthIntegrity, append(d, salt...))
	if len(ciphers) > 0 {
		d = binary.LittleEndian.AppendUint16(nil, uint16(len(ciphers)))
		for _, c := range ciphers {
			d = binary.LittleEndian.AppendUint16(d, c)
		}
		ctx(ctxEncryption, d)
	}
	d = binary.LittleEndian.AppendUint16(nil, uint16(len(signs)))
	for _, s := range signs {
		d = binary.LittleEndian.AppendUint16(d, s)
	}
	ctx(ctxSigning, d)
	return out, n
}

// ─── SESSION_SETUP, TREE_CONNECT ─────────────────────────────────────────────

func clSessionSetupRequest(secMode uint8, token []byte) []byte {
	b := make([]byte, 24, 24+len(token))
	binary.LittleEndian.PutUint16(b[0:], 25)
	b[3] = secMode
	binary.LittleEndian.PutUint16(b[12:], headerLen+24)
	binary.LittleEndian.PutUint16(b[14:], uint16(len(token)))
	return append(b, token...)
}

func parseSessionSetupResp(msg []byte) (flags uint16, sec []byte, err error) {
	b, err := body(msg, 8, 9)
	if err != nil {
		return 0, nil, err
	}
	sec, err = buf(msg, int(le16(b[4:])), int(le16(b[6:])), headerLen+8)
	return le16(b[2:]), sec, err
}

func clTreeConnectRequest(unc string) []byte {
	name := utf16leBytes(unc)
	b := make([]byte, 8, 8+len(name))
	binary.LittleEndian.PutUint16(b[0:], 9)
	binary.LittleEndian.PutUint16(b[4:], headerLen+8)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(name)))
	return append(b, name...)
}

type clTree struct {
	shareType byte
	flags     uint32
	caps      uint32
	access    uint32
}

func parseTreeConnectResp(msg []byte) (clTree, error) {
	b, err := body(msg, 16, 16)
	if err != nil {
		return clTree{}, err
	}
	return clTree{b[2], le32(b[4:]), le32(b[8:]), le32(b[12:])}, nil
}

// ─── CREATE, CLOSE ───────────────────────────────────────────────────────────

// Access, share, disposition and option bits of CREATE ([MS-SMB2] 2.2.13).
const (
	accReadData       = 0x00000001
	accReadAttributes = 0x00000080
	accWriteData      = 0x00000002
	accDelete         = 0x00010000
	accListDirectory  = accReadData
	accSynchronize    = 0x00100000

	shareAll = 0x7

	optDirectory    = 0x00000001
	optNonDirectory = 0x00000040
	optOpenReparse  = 0x00200000

	attrReparse = 0x400
)

func clCreateRequest(name string, access, attrs, disp, opts uint32) []byte {
	n := utf16leBytes(name)
	b := make([]byte, 56, 56+len(n)+1)
	binary.LittleEndian.PutUint16(b[0:], 57)
	binary.LittleEndian.PutUint32(b[4:], 2) // ImpersonationLevel: Impersonation
	binary.LittleEndian.PutUint32(b[24:], access)
	binary.LittleEndian.PutUint32(b[28:], attrs)
	binary.LittleEndian.PutUint32(b[32:], shareAll)
	binary.LittleEndian.PutUint32(b[36:], disp)
	binary.LittleEndian.PutUint32(b[40:], opts)
	binary.LittleEndian.PutUint16(b[44:], headerLen+56)
	binary.LittleEndian.PutUint16(b[46:], uint16(len(n)))
	b = append(b, n...)
	if len(n) == 0 {
		b = append(b, 0) // the buffer is at least one byte, even for the root
	}
	return b
}

type clCreated struct {
	id         [16]byte
	attrs      uint32
	eof        uint64
	mtime      uint64 // FILETIME
	oplockless bool
}

func parseCreateResp(msg []byte) (clCreated, error) {
	var c clCreated
	b, err := body(msg, 88, 89)
	if err != nil {
		return c, err
	}
	c.mtime = le64(b[24:])
	c.eof = le64(b[48:])
	c.attrs = le32(b[56:])
	copy(c.id[:], b[64:80])
	return c, nil
}

func clCloseRequest(id [16]byte) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b[0:], 24)
	copy(b[8:], id[:])
	return b
}

// ─── QUERY_INFO, QUERY_DIRECTORY ─────────────────────────────────────────────

const (
	fsFullSizeInfo    = 7
	fileDirectoryInfo = 1
)

func clQueryInfoRequest(infoType, class uint8, out uint32, id [16]byte) []byte {
	b := make([]byte, 41)
	binary.LittleEndian.PutUint16(b[0:], 41)
	b[2], b[3] = infoType, class
	binary.LittleEndian.PutUint32(b[4:], out)
	binary.LittleEndian.PutUint16(b[8:], headerLen+40)
	copy(b[24:], id[:])
	return b
}

// parseInfoResp is the output buffer of a QUERY_INFO or QUERY_DIRECTORY
// response, whose layouts agree on the three fields (structure size 9).
func parseInfoResp(msg []byte) ([]byte, error) {
	b, err := body(msg, 8, 9)
	if err != nil {
		return nil, err
	}
	return buf(msg, int(le16(b[2:])), int(le32(b[4:])), headerLen+8)
}

// clFullSize is FileFsFullSizeInformation ([MS-FSCC] 2.5.4).
type clFullSize struct {
	unit, total, free, avail uint64
}

func parseFullSize(b []byte) (clFullSize, error) {
	if len(b) < 32 {
		return clFullSize{}, errShort
	}
	spu, bps := uint64(le32(b[24:])), uint64(le32(b[28:]))
	return clFullSize{spu * bps, le64(b), le64(b[16:]), le64(b[8:])}, nil
}

func clQueryDirRequest(id [16]byte, restart bool, out uint32) []byte {
	pat := utf16leBytes("*")
	b := make([]byte, 32, 32+len(pat))
	binary.LittleEndian.PutUint16(b[0:], 33)
	b[2] = fileDirectoryInfo
	if restart {
		b[3] = 0x01
	}
	copy(b[8:], id[:])
	binary.LittleEndian.PutUint16(b[24:], headerLen+32)
	binary.LittleEndian.PutUint16(b[26:], uint16(len(pat)))
	binary.LittleEndian.PutUint32(b[28:], out)
	return append(b, pat...)
}

// ClientDirEntry is one entry of a directory listing.
type ClientDirEntry struct {
	Name    string
	Size    int64
	Attrs   uint32
	ModTime time.Time
}

// IsDir and IsReparse read the FILE_ATTRIBUTE bits.
func (e ClientDirEntry) IsDir() bool     { return e.Attrs&attrDirectory != 0 }
func (e ClientDirEntry) IsReparse() bool { return e.Attrs&attrReparse != 0 }

// fileTime converts a FILETIME; zero and the values before the Unix epoch's
// representable range give the zero time.
func fileTime(ft uint64) time.Time {
	const delta = 11644473600
	if ft == 0 || ft/10_000_000 < delta {
		return time.Time{}
	}
	return time.Unix(int64(ft/10_000_000)-delta, int64(ft%10_000_000)*100)
}

// parseDirEntries decodes a FileDirectoryInformation list ([MS-FSCC] 2.4.10):
// each entry is at least 64 bytes plus its name, NextEntryOffset moves strictly
// forward past the name, and the last is 0. "." and ".." are kept (the caller drops them, after checking
// the batch was not empty). A walk
// that would not terminate or would read outside the buffer is an error.
func parseDirEntries(b []byte) ([]ClientDirEntry, error) {
	var out []ClientDirEntry
	off := 0
	for more := true; more; {
		if off > len(b)-64 {
			return out, errShort
		}
		e := b[off:]
		next := int(le32(e))
		nl := int(le32(e[60:]))
		if nl%2 != 0 || nl > len(e)-64 {
			return out, errBadField
		}
		if next != 0 && (next < 64+nl || next > len(e)) {
			return out, errBadField
		}
		name := string(utf16.Decode(clU16s(e[64 : 64+nl])))
		sz := le64(e[40:])
		if sz > 1<<63-1 {
			sz = 0
		}
		out = append(out, ClientDirEntry{name, int64(sz), le32(e[56:]), fileTime(le64(e[24:]))})
		more = next != 0
		off += next
	}
	return out, nil
}

func clU16s(b []byte) []uint16 {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le16(b[2*i:])
	}
	return u
}

// ─── READ, WRITE ─────────────────────────────────────────────────────────────

func clReadRequest(id [16]byte, off uint64, n uint32) []byte {
	b := make([]byte, 49)
	binary.LittleEndian.PutUint16(b[0:], 49)
	b[2] = headerLen + 16 // Padding: where the data should sit
	binary.LittleEndian.PutUint32(b[4:], n)
	binary.LittleEndian.PutUint64(b[8:], off)
	copy(b[16:], id[:])
	return b
}

// parseReadResp returns the data of a READ response; want is the length
// asked for, which a server must not exceed.
func parseReadResp(msg []byte, want uint32) ([]byte, error) {
	b, err := body(msg, 16, 17)
	if err != nil {
		return nil, err
	}
	n := le32(b[4:])
	if n > want {
		return nil, fmt.Errorf("smb: server returned %d bytes for a %d-byte read", n, want)
	}
	return buf(msg, int(b[2]), int(n), headerLen+16)
}

func clWriteRequest(id [16]byte, off uint64, data []byte) []byte {
	b := make([]byte, 48, 48+len(data))
	binary.LittleEndian.PutUint16(b[0:], 49)
	binary.LittleEndian.PutUint16(b[2:], headerLen+48)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(data)))
	binary.LittleEndian.PutUint64(b[8:], off)
	copy(b[16:], id[:])
	return append(b, data...)
}

func parseWriteResp(msg []byte) (uint32, error) {
	b, err := body(msg, 16, 17)
	if err != nil {
		return 0, err
	}
	return le32(b[4:]), nil
}

// clEmptyRequest is the 4-byte body of TREE_DISCONNECT and LOGOFF.
func clEmptyRequest() []byte { return []byte{4, 0, 0, 0} }

// clPath makes the SMB name of a slash-separated relative path. It refuses what
// would let a caller walk out of the share ("..", a rooted path, NUL), which a
// server also refuses but which a client must not rely on.
func clPath(p string) (string, error) {
	parts := make([]string, 0, 8)
	start := 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			c := p[start:i]
			start = i + 1
			if c == "" || c == "." {
				continue
			}
			if c == ".." {
				return "", fmt.Errorf("smb: path %q goes above the share root", p)
			}
			parts = append(parts, c)
		}
	}
	for _, c := range parts {
		for j := 0; j < len(c); j++ {
			if c[j] == 0 || c[j] == '\\' {
				return "", fmt.Errorf("smb: path %q holds a separator or NUL inside a name", p)
			}
		}
	}
	return joinBackslash(parts), nil
}

func joinBackslash(parts []string) string {
	n := len(parts)
	for _, s := range parts {
		n += len(s)
	}
	b := make([]byte, 0, n)
	for i, s := range parts {
		if i > 0 {
			b = append(b, '\\')
		}
		b = append(b, s...)
	}
	return string(b)
}
