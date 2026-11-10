// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"encoding/binary"
	"log/slog"
	"strconv"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// SET_INFO with FileBasicInformation, the times half.
//
// Sources, all read before this was written:
//
//   - [MS-FSCC] 2.4.7 FileBasicInformation: each of the four times is "an
//     integer greater than or equal to 0"; 0 "MUST NOT change this attribute";
//     -1 "MUST NOT change this attribute for all subsequent operations on the
//     same file handle"; -2 "MUST change this attribute for all subsequent
//     operations on the same file handle"; "MUST NOT be set to a value less
//     than -2".
//   - [MS-FSA] 2.1.5.15.2 FileBasicInformation: the pseudocode. Less than -2 is
//     STATUS_INVALID_PARAMETER; a buffer shorter than FILE_BASIC_INFORMATION is
//     STATUS_INFO_LENGTH_MISMATCH; any value other than 0 and -2 (a real time as
//     well as -1) sets the handle's UserSet* flag, and -2 clears it.
//   - [MS-SMB2] 3.3.5.21.1 Handling SMB2_0_INFO_FILE: "If the store does not
//     support the information class requested, the server MUST fail the request
//     with STATUS_NOT_SUPPORTED."; "If the underlying object store returns an
//     error, the server MUST fail the request with the error code received."
//   - Samba's smb_set_file_time (source3/smbd/smb2_trans2.c), read for
//     understanding: a zero or -1 time is "omitted" and nothing is changed for it.
//
// The only setter the filesystem interface has is
// MetadataSetter.Chtimes(path, atime, mtime): it sets the access and write
// times, and "ctime is refreshed to now"; there is no creation or change time
// setter. So:
//
//   - LastAccessTime and LastWriteTime are applied through Chtimes.
//   - CreationTime is applied to nothing, and ChangeTime only as Chtimes'
//     refresh to now. A real CreationTime is STATUS_NOT_SUPPORTED, and NOTHING
//     is applied for that request (the checks all run before the first write),
//     so a backup tool is never told a time was kept when it was not; so is a
//     real ChangeTime with no access or write time to refresh it. An exception
//     for both: a value equal to the one the driver already reports through
//     TimesReader, for there is nothing to change.
//   - 0 is "keep"; -1 and -2 are implemented per handle (see openFile.pinned).

// timeKind says what one FILETIME field of FILE_BASIC_INFORMATION asks for.
type timeKind uint8

const (
	timeKeep   timeKind = iota // 0: do not change
	timeSet                    // >0: set it
	timeHold                   // -1: stop updating it on this handle
	timeResume                 // -2: resume updating it on this handle
)

// timeSpec is one decoded field.
type timeSpec struct {
	kind timeKind
	ft   uint64 // the FILETIME, only for timeSet
}

// basicInfo is a decoded FILE_BASIC_INFORMATION. FileAttributes is not here:
// attributes are still accepted and dropped.
type basicInfo struct {
	creation, access, write, change timeSpec
}

// fileBasicInfoLen is sizeof(FILE_BASIC_INFORMATION): four FILETIMEs, the
// attributes and a reserved word.
const fileBasicInfoLen = 40

const statusInfoLengthMismatch uint32 = 0xC0000004

func decodeTimeSpec(v uint64) (timeSpec, bool) {
	switch s := int64(v); {
	case s == 0:
		return timeSpec{kind: timeKeep}, true
	case s == -1:
		return timeSpec{kind: timeHold}, true
	case s == -2:
		return timeSpec{kind: timeResume}, true
	case s < -2:
		return timeSpec{}, false
	default:
		return timeSpec{kind: timeSet, ft: v}, true
	}
}

// decodeBasicInfo reads FILE_BASIC_INFORMATION. It returns statusSuccess, or
// the status [MS-FSA] gives: STATUS_INFO_LENGTH_MISMATCH for a short buffer and
// STATUS_INVALID_PARAMETER for any time below -2. Bytes past 40 are ignored.
func decodeBasicInfo(in []byte) (basicInfo, uint32) {
	var bi basicInfo
	if len(in) < fileBasicInfoLen {
		return bi, statusInfoLengthMismatch
	}
	for i, dst := range []*timeSpec{&bi.creation, &bi.access, &bi.write, &bi.change} {
		s, ok := decodeTimeSpec(binary.LittleEndian.Uint64(in[i*8:]))
		if !ok {
			return basicInfo{}, statusInvalidParameter
		}
		*dst = s
	}
	return bi, statusSuccess
}

// timeOfFiletime is the inverse of filetime.
func timeOfFiletime(ft uint64) time.Time {
	const epochDelta = 11644473600
	return time.Unix(int64(ft/10_000_000)-epochDelta, int64(ft%10_000_000)*100).UTC()
}

// pinned is the value of a time a client froze on one handle (-1, or a value it
// set): later writes through the handle must not move it.
type pinned struct {
	on bool
	t  time.Time
}

// setBasicTimes applies the times of a FILE_BASIC_INFORMATION to of. It returns
// the status for the SET_INFO response. Nothing is applied unless everything
// asked for can be.
func (c *conn) setBasicTimes(of *openFile, bi basicInfo) uint32 {
	fsys := of.share.fsys
	cur := timesOf(fsys, of.path)
	setter, canSet := fsys.(filesystem.MetadataSetter)

	// CreationTime and ChangeTime have no setter. A client that asks for one
	// that is not already so hears it.
	//
	// ChangeTime has one more way out. The Linux kernel client puts "now" in it
	// on every utimensat (the VFS sets ATTR_CTIME), and Samba ignores the field
	// for the same reason. A change time is the server's own clock: Chtimes
	// "refreshes ctime to now", which is what the client is asking for within
	// the round trip. So a ChangeTime that rides along with an access or write
	// time that IS applied is accepted; on its own it is refused like a creation
	// time, because then nothing would run to refresh it.
	//
	// What cannot be stored is handled by the share's [TimePolicy]: dropped (the
	// default), dropped and logged, or refused whole.
	var dropped []string
	logDropped := false
	refreshed := bi.access.kind == timeSet || bi.write.kind == timeSet
	for i, f := range []struct {
		spec timeSpec
		have func(*filesystem.FileTimes) filesystem.Timestamp
		name string
	}{
		{bi.creation, func(t *filesystem.FileTimes) filesystem.Timestamp { return t.Btime }, "CreationTime"},
		{bi.change, func(t *filesystem.FileTimes) filesystem.Timestamp { return t.Ctime }, "ChangeTime"},
	} {
		if i == 1 && refreshed && canSet {
			continue
		}
		if f.spec.kind != timeSet {
			// 0, -1 and -2 change nothing here. (-1 on ChangeTime asks that this
			// handle's writes not refresh it; Chtimes refreshes ctime and a driver
			// may do so on a write, which is not something this server can stop.)
			continue
		}
		if cur == nil || filetimeOf(f.have(cur)) != f.spec.ft {
			dropped = append(dropped, f.name)
		}
	}

	type want struct {
		spec timeSpec
		pin  *pinned
		have filesystem.Timestamp
	}
	var haveA, haveW filesystem.Timestamp
	if cur != nil {
		haveA, haveW = cur.Atime, cur.Mtime
	}
	fields := []want{{bi.access, &of.pinAccess, haveA}, {bi.write, &of.pinWrite, haveW}}

	set := false
	for i, f := range fields {
		switch f.spec.kind {
		case timeSet:
			set = true
			if !canSet {
				dropped = append(dropped, [...]string{"LastAccessTime", "LastWriteTime"}[i])
			}
		case timeHold:
			// Freezing a value needs the value, and a way to put it back. This is
			// a capability gap, not a stored field being dropped, so it is refused
			// whatever the policy says.
			if canSet && (cur == nil) {
				return statusNotSupported
			}
		}
	}
	if len(dropped) > 0 {
		if of.share.timePolicy == TimesRefuse {
			return statusNotSupported
		}
		logDropped = of.share.timePolicy == TimesLog
	}
	if !canSet {
		set = false // nothing to call; the real times were dropped above
	}

	// Chtimes treats a zero time.Time as "leave unchanged" (interface
	// times.go), so a field the client did not set is the driver's own current
	// value when it can be read, and zero otherwise.
	var t [2]time.Time
	if set {
		for i, f := range fields {
			if f.spec.kind == timeSet {
				t[i] = timeOfFiletime(f.spec.ft)
			} else if v, ok := f.have.Get(); ok {
				t[i] = v
			}
		}
		if err := setter.Chtimes(of.path, t[0], t[1]); err != nil {
			return statusFor(err, statusNotSupported)
		}
		if after := timesOf(fsys, of.path); after != nil {
			haveA, haveW = after.Atime, after.Mtime
			fields[0].have, fields[1].have = haveA, haveW
		}
	}
	for i, f := range fields {
		switch f.spec.kind {
		case timeSet:
			// The driver may have rounded it (FAT keeps the write time to 2 s):
			// the handle keeps what the driver now holds.
			if v, ok := f.have.Get(); ok {
				*f.pin = pinned{true, v}
			} else {
				*f.pin = pinned{true, t[i]}
			}
		case timeHold:
			if v, ok := f.have.Get(); ok && canSet {
				*f.pin = pinned{true, v}
			}
		case timeResume:
			*f.pin = pinned{}
		}
	}
	if logDropped {
		c.logDropped(of, dropped)
	}
	return statusSuccess
}

// TimePolicy says what a share does with a time a client sets and the server
// cannot store: a CreationTime (the filesystem interface has no setter for it),
// a ChangeTime on its own (it is the server's own clock; see setBasicTimes), and
// a LastAccessTime or LastWriteTime on a driver without
// [filesystem.MetadataSetter]. The zero value is [TimesIgnore].
//
// It does not cover -1 on a driver that has Chtimes but no
// [filesystem.TimesReader]: that is a capability gap (the value to freeze cannot
// be read), not a stored field being dropped, and it is always
// STATUS_NOT_SUPPORTED. Nor does it change how malformed values are answered.
type TimePolicy uint8

const (
	// TimesIgnore answers success and drops the unstorable fields silently, as
	// Samba's smb_set_file_time does, so a copy that preserves times (Windows
	// Explorer, robocopy /COPY:T) keeps working. It is the default.
	TimesIgnore TimePolicy = iota
	// TimesRefuse answers STATUS_NOT_SUPPORTED (MS-SMB2 3.3.5.21.1) and applies
	// nothing in that request, so a backup tool never believes an unstored time
	// was kept.
	TimesRefuse
	// TimesLog is TimesIgnore plus one structured slog line per request, naming
	// the share, the path and each dropped field. The path is client-supplied and
	// is written quoted and ASCII-escaped, so it cannot forge a log line.
	TimesLog
)

// UnstorableTimes sets the share's [TimePolicy].
func UnstorableTimes(p TimePolicy) ShareOption { return func(s *share) { s.timePolicy = p } }

// logDropped writes the TimesLog line to the server's Logger.
func (c *conn) logDropped(of *openFile, fields []string) {
	l := slog.Default()
	if c.srv != nil && c.srv.Logger != nil {
		l = c.srv.Logger
	}
	l.Warn("smb: SET_INFO times not stored",
		"share", strconv.QuoteToASCII(of.share.name),
		"path", strconv.QuoteToASCII(of.path),
		"fields", fields)
}

// restorePinned puts back the times this handle froze, after something that the
// driver may have stamped (a write, a resize, the close). It is what -1 means:
// [MS-FSCC] 2.4.7 "MUST NOT change this attribute for all subsequent operations
// on the same file handle". A failure is ignored: the data is already written
// and the client was not promised more than "the server tried".
func (c *conn) restorePinned(of *openFile) {
	if of == nil || (!of.pinAccess.on && !of.pinWrite.on) || of.share == nil || of.share.fsys == nil {
		return
	}
	setter, ok := of.share.fsys.(filesystem.MetadataSetter)
	if !ok {
		return
	}
	cur := timesOf(of.share.fsys, of.path)
	var t [2]time.Time
	differs := false
	for i, p := range []struct {
		pin  pinned
		have func(*filesystem.FileTimes) filesystem.Timestamp
	}{
		{of.pinAccess, func(f *filesystem.FileTimes) filesystem.Timestamp { return f.Atime }},
		{of.pinWrite, func(f *filesystem.FileTimes) filesystem.Timestamp { return f.Mtime }},
	} {
		if !p.pin.on {
			continue
		}
		t[i] = p.pin.t
		if cur == nil {
			differs = true
		} else if v, ok := p.have(cur).Get(); !ok || !v.Equal(p.pin.t) {
			differs = true
		}
	}
	if differs {
		_ = setter.Chtimes(of.path, t[0], t[1])
	}
}
