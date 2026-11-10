package smb

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// chtFS is tinyFS plus the write side of the times (MetadataSetter) and, as
// chtTimesFS, the read side. A WriteFile stamps the write time with a fixed
// "now", the way a driver that records times does.
type chtFS struct {
	*tinyFS
	a, m, b, c time.Time // what the driver records
	calls      [][2]time.Time
	err        error
}

var stampNow = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func (f *chtFS) Chmod(string, os.FileMode) error    { return nil }
func (f *chtFS) Chown(string, uint32, uint32) error { return nil }
func (f *chtFS) Chtimes(_ string, a, m time.Time) error {
	f.calls = append(f.calls, [2]time.Time{a, m})
	if f.err != nil {
		return f.err
	}
	if !a.IsZero() {
		f.a = a
	}
	if !m.IsZero() {
		f.m = m
	}
	return nil
}
func (f *chtFS) WriteFile(p string, d []byte, mode os.FileMode) error {
	f.m = stampNow
	return f.tinyFS.WriteFile(p, d, mode)
}

type chtTimesFS struct{ *chtFS }

func (f chtTimesFS) Times(string) (filesystem.FileTimes, error) {
	ts := func(t time.Time) filesystem.Timestamp { return filesystem.NewTimestamp(t, time.Nanosecond) }
	return filesystem.FileTimes{Atime: ts(f.a), Mtime: ts(f.m), Btime: ts(f.b), Ctime: ts(f.c)}, nil
}

func ft(t time.Time) uint64 { return filetime(t) }

var (
	t0 = time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	t1 = time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 = time.Date(2020, 6, 7, 8, 9, 10, 500, time.UTC)
	m1 = ^uint64(0) // -1
	m2 = ^uint64(1) // -2
	m3 = ^uint64(2) // -3
)

func basic(cr, a, w, ch uint64) []byte {
	b := make([]byte, 40)
	for i, v := range []uint64{cr, a, w, ch} {
		binary.LittleEndian.PutUint64(b[i*8:], v)
	}
	return b
}

func setBasic(t *testing.T, c *conn, of *openFile, in []byte) uint32 {
	t.Helper()
	body := make([]byte, 32)
	body[2], body[3] = infoTypeFile, fileBasicInformationSet
	binary.LittleEndian.PutUint32(body[4:], uint32(len(in)))
	binary.LittleEndian.PutUint16(body[8:], uint16(headerLen+32))
	copy(body[16:], of.id[:])
	out, err := c.dispatch(request(cmdSetInfo, 1, append(body, in...)))
	if err != nil {
		t.Fatal(err)
	}
	return statusOf(t, out)
}

func writeThrough(t *testing.T, c *conn, of *openFile) {
	t.Helper()
	body := make([]byte, 48)
	binary.LittleEndian.PutUint16(body[2:], uint16(headerLen+48))
	binary.LittleEndian.PutUint32(body[4:], 1)
	copy(body[16:], of.id[:])
	out, err := c.dispatch(request(cmdWrite, 1, append(body, 'x')))
	if err != nil {
		t.Fatal(err)
	}
	if st := statusOf(t, out); st != statusSuccess {
		t.Fatalf("write answered %#x", st)
	}
}

func newCht(t *testing.T, reader bool) (*conn, *openFile, *chtFS) {
	t.Helper()
	f := &chtFS{tinyFS: &tinyFS{body: []byte("hello")}, a: t1, m: t1, b: t1, c: t1}
	if reader {
		c, of := opened(t, chtTimesFS{f}, "/file.txt", false)
		return c, of, f
	}
	c, of := opened(t, f, "/file.txt", false)
	return c, of, f
}

// Every value of one field, alone, with a driver that can set and read.
func TestSetInfoBasicTimes(t *testing.T) {
	tests := []struct {
		name      string
		in        []byte
		want      uint32
		wantA     time.Time
		wantM     time.Time
		wantCalls int
	}{
		{"all zero is do not change", basic(0, 0, 0, 0), statusSuccess, t1, t1, 0},
		{"write only keeps access", basic(0, 0, ft(t0), 0), statusSuccess, t1, t0, 1},
		{"access only keeps write", basic(0, ft(t2), 0, 0), statusSuccess, t2, t1, 1},
		{"both", basic(0, ft(t2), ft(t0), 0), statusSuccess, t2, t0, 1},
		{"-1 changes nothing now", basic(0, m1, m1, 0), statusSuccess, t1, t1, 0},
		{"-2 changes nothing now", basic(0, m2, m2, 0), statusSuccess, t1, t1, 0},
		{"set one, hold other", basic(0, m1, ft(t0), 0), statusSuccess, t1, t0, 1},
		{"-1 and -2 on creation and change are no-ops", basic(m1, 0, ft(t0), m2), statusSuccess, t1, t0, 1},
		{"below -2 access", basic(0, m3, 0, 0), statusInvalidParameter, t1, t1, 0},
		{"below -2 write", basic(0, 0, m3, 0), statusInvalidParameter, t1, t1, 0},
		{"below -2 creation", basic(m3, 0, ft(t0), 0), statusInvalidParameter, t1, t1, 0},
		{"below -2 change", basic(0, 0, ft(t0), 1<<63), statusInvalidParameter, t1, t1, 0},
		{"short buffer", make([]byte, 39), statusInfoLengthMismatch, t1, t1, 0},
		{"creation differs: nothing applied", basic(ft(t0), 0, ft(t2), 0), statusNotSupported, t1, t1, 0},
		{"change alone: nothing refreshes it", basic(0, 0, 0, ft(t0)), statusNotSupported, t1, t1, 0},
		{"change rides along with an applied write time (the kernel's touch)", basic(0, 0, ft(t2), ft(t0)), statusSuccess, t1, t2, 1},
		{"creation equal to the recorded one is nothing to do", basic(ft(t1), 0, ft(t2), ft(t1)), statusSuccess, t1, t2, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, of, f := newCht(t, true)
			of.share.timePolicy = TimesRefuse // the table is about the strict answers
			if got := setBasic(t, c, of, tc.in); got != tc.want {
				t.Fatalf("status %#x, want %#x", got, tc.want)
			}
			if !f.a.Equal(tc.wantA) || !f.m.Equal(tc.wantM) {
				t.Errorf("atime %v mtime %v, want %v %v", f.a, f.m, tc.wantA, tc.wantM)
			}
			if len(f.calls) != tc.wantCalls {
				t.Errorf("%d Chtimes calls, want %d", len(f.calls), tc.wantCalls)
			}
		})
	}
}

func TestSetInfoTimesDriverShapes(t *testing.T) {
	t.Run("no setter: a real time is NOT_SUPPORTED under TimesRefuse", func(t *testing.T) {
		c, of := opened(t, &tinyFS{body: []byte("x")}, "/file.txt", false)
		of.share.timePolicy = TimesRefuse
		if got := setBasic(t, c, of, basic(0, 0, ft(t0), 0)); got != statusNotSupported {
			t.Errorf("status %#x", got)
		}
	})
	t.Run("no setter: nothing to apply succeeds", func(t *testing.T) {
		c, of := opened(t, &tinyFS{body: []byte("x")}, "/file.txt", false)
		for _, in := range [][]byte{basic(0, 0, 0, 0), basic(m1, m1, m2, m1)} {
			if got := setBasic(t, c, of, in); got != statusSuccess {
				t.Errorf("status %#x", got)
			}
		}
	})
	t.Run("setter without reader: set passes the other as zero", func(t *testing.T) {
		c, of, f := newCht(t, false)
		if got := setBasic(t, c, of, basic(0, 0, ft(t0), 0)); got != statusSuccess {
			t.Fatalf("status %#x", got)
		}
		if !f.calls[0][0].IsZero() || !f.calls[0][1].Equal(t0) {
			t.Errorf("Chtimes(%v)", f.calls[0])
		}
	})
	t.Run("setter without reader: -1 cannot be honoured", func(t *testing.T) {
		c, of, _ := newCht(t, false)
		if got := setBasic(t, c, of, basic(0, 0, m1, 0)); got != statusNotSupported {
			t.Errorf("status %#x", got)
		}
	})
	t.Run("driver error is the answer", func(t *testing.T) {
		c, of, f := newCht(t, true)
		f.err = errors.New("boom")
		if got := setBasic(t, c, of, basic(0, 0, ft(t0), 0)); got == statusSuccess {
			t.Error("a failed Chtimes was reported as success")
		}
	})
	t.Run("read-only handle", func(t *testing.T) {
		c, of := opened(t, &chtFS{tinyFS: &tinyFS{body: []byte("x")}}, "/file.txt", true)
		if got := setBasic(t, c, of, basic(0, 0, ft(t0), 0)); got != statusMediaWriteProtected {
			t.Errorf("status %#x", got)
		}
	})
}

// -1 freezes a time on the handle until -2; a value set freezes it too (MS-FSA
// UserSet*), and the close keeps it.
func TestSetInfoTimesPerHandle(t *testing.T) {
	t.Run("without -1 a write moves mtime", func(t *testing.T) {
		c, of, f := newCht(t, true)
		writeThrough(t, c, of)
		if !f.m.Equal(stampNow) {
			t.Errorf("mtime %v", f.m)
		}
	})
	t.Run("-1 holds it through writes", func(t *testing.T) {
		c, of, f := newCht(t, true)
		if got := setBasic(t, c, of, basic(0, 0, m1, 0)); got != statusSuccess {
			t.Fatal(got)
		}
		writeThrough(t, c, of)
		if !f.m.Equal(t1) {
			t.Errorf("mtime %v moved under -1", f.m)
		}
	})
	t.Run("-2 resumes", func(t *testing.T) {
		c, of, f := newCht(t, true)
		setBasic(t, c, of, basic(0, 0, m1, 0))
		setBasic(t, c, of, basic(0, 0, m2, 0))
		writeThrough(t, c, of)
		if !f.m.Equal(stampNow) {
			t.Errorf("mtime %v did not resume", f.m)
		}
	})
	t.Run("a set value is kept through the write", func(t *testing.T) {
		c, of, f := newCht(t, true)
		setBasic(t, c, of, basic(0, 0, ft(t0), 0))
		writeThrough(t, c, of)
		if !f.m.Equal(t0) {
			t.Errorf("mtime %v", f.m)
		}
	})
	t.Run("kept through a resize and the close", func(t *testing.T) {
		c, of, f := newCht(t, true)
		setBasic(t, c, of, basic(0, 0, ft(t0), 0))
		size := make([]byte, 8)
		binary.LittleEndian.PutUint64(size, 2)
		body := make([]byte, 32)
		body[2], body[3] = infoTypeFile, fileEndOfFileInformation
		binary.LittleEndian.PutUint32(body[4:], 8)
		binary.LittleEndian.PutUint16(body[8:], uint16(headerLen+32))
		copy(body[16:], of.id[:])
		if _, err := c.dispatch(request(cmdSetInfo, 1, append(body, size...))); err != nil {
			t.Fatal(err)
		}
		if !f.m.Equal(t0) {
			t.Errorf("mtime %v after the resize", f.m)
		}
		f.m = stampNow // something stamps it before the close
		cl := make([]byte, 24)
		copy(cl[8:], of.id[:])
		if _, err := c.dispatch(request(cmdClose, 1, cl)); err != nil {
			t.Fatal(err)
		}
		if !f.m.Equal(t0) {
			t.Errorf("mtime %v after the close", f.m)
		}
	})
}

func TestTimeOfFiletimeRoundTrip(t *testing.T) {
	for _, tm := range []time.Time{t0, t2, time.Unix(0, 0).UTC(), time.Date(1601, 1, 1, 0, 0, 1, 0, time.UTC)} {
		if got := timeOfFiletime(filetime(tm)); !got.Equal(tm.Truncate(100 * time.Nanosecond)) {
			t.Errorf("%v -> %v", tm, got)
		}
	}
}

// FuzzDecodeBasicInfo: whatever the bytes, the decoder neither panics nor
// accepts a buffer below 40 bytes or a time below -2, and a decoded field is
// exactly one of the four kinds.
func FuzzDecodeBasicInfo(f *testing.F) {
	f.Add(basic(0, 0, 0, 0))
	f.Add(basic(m1, m1, m1, m1))
	f.Add(basic(m2, m2, m2, m2))
	f.Add(basic(m3, 0, 0, 0))
	f.Add(basic(ft(t0), ft(t1), ft(t2), 1<<63))
	f.Add(make([]byte, 39))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		bi, st := decodeBasicInfo(in)
		if len(in) < 40 {
			if st != statusInfoLengthMismatch {
				t.Fatalf("%d bytes answered %#x", len(in), st)
			}
			return
		}
		var below bool
		for i := 0; i < 4; i++ {
			if int64(binary.LittleEndian.Uint64(in[i*8:])) < -2 {
				below = true
			}
		}
		if below != (st == statusInvalidParameter) || (!below && st != statusSuccess) {
			t.Fatalf("below=%v status %#x", below, st)
		}
		if st != statusSuccess {
			return
		}
		for i, s := range []timeSpec{bi.creation, bi.access, bi.write, bi.change} {
			v := binary.LittleEndian.Uint64(in[i*8:])
			ok := (s.kind == timeKeep && v == 0) || (s.kind == timeHold && v == m1) ||
				(s.kind == timeResume && v == m2) || (s.kind == timeSet && s.ft == v && int64(v) > 0)
			if !ok {
				t.Fatalf("field %d: %+v from %#x", i, s, v)
			}
			if s.kind == timeSet {
				_ = timeOfFiletime(s.ft) // must not panic
			}
		}
	})
}

// Each mode of TimePolicy against each case that is a stored field being
// dropped, and against the one that is not (-1 without a reader).
func TestTimePolicyModesAndCases(t *testing.T) {
	type outcome struct {
		status  uint32
		applied bool     // the write time reached the driver
		logged  []string // the fields in the log line, nil for no line
	}
	cases := []struct {
		name   string
		driver string // "full", "bare" (no setter), "noreader"
		in     []byte
		ignore outcome
		refuse outcome
		log    outcome
	}{
		{"creation differs, write set", "full", basic(ft(t0), 0, ft(t2), 0),
			outcome{statusSuccess, true, nil}, outcome{statusNotSupported, false, nil}, outcome{statusSuccess, true, []string{"CreationTime"}}},
		{"change alone", "full", basic(0, 0, 0, ft(t0)),
			outcome{statusSuccess, false, nil}, outcome{statusNotSupported, false, nil}, outcome{statusSuccess, false, []string{"ChangeTime"}}},
		{"creation and change alone", "full", basic(ft(t0), 0, 0, ft(t0)),
			outcome{statusSuccess, false, nil}, outcome{statusNotSupported, false, nil}, outcome{statusSuccess, false, []string{"CreationTime", "ChangeTime"}}},
		{"creation equals the recorded one", "full", basic(ft(t1), 0, ft(t2), ft(t1)),
			outcome{statusSuccess, true, nil}, outcome{statusSuccess, true, nil}, outcome{statusSuccess, true, nil}},
		{"no setter, write and access set", "bare", basic(0, ft(t2), ft(t2), 0),
			outcome{statusSuccess, false, nil}, outcome{statusNotSupported, false, nil}, outcome{statusSuccess, false, []string{"LastAccessTime", "LastWriteTime"}}},
		{"no setter, change rides along", "bare", basic(0, 0, ft(t2), ft(t0)),
			outcome{statusSuccess, false, nil}, outcome{statusNotSupported, false, nil}, outcome{statusSuccess, false, []string{"ChangeTime", "LastWriteTime"}}},
		{"-1 with a setter and no reader is a capability gap", "noreader", basic(0, 0, m1, 0),
			outcome{statusNotSupported, false, nil}, outcome{statusNotSupported, false, nil}, outcome{statusNotSupported, false, nil}},
		{"nothing to store", "full", basic(0, 0, 0, 0),
			outcome{statusSuccess, false, nil}, outcome{statusSuccess, false, nil}, outcome{statusSuccess, false, nil}},
	}
	for _, tc := range cases {
		for _, mode := range []struct {
			name string
			p    TimePolicy
			want func() outcome
		}{
			{"ignore", TimesIgnore, func() outcome { return tc.ignore }},
			{"refuse", TimesRefuse, func() outcome { return tc.refuse }},
			{"log", TimesLog, func() outcome { return tc.log }},
		} {
			t.Run(tc.name+"/"+mode.name, func(t *testing.T) {
				var c *conn
				var of *openFile
				var f *chtFS
				switch tc.driver {
				case "full":
					c, of, f = newCht(t, true)
				case "noreader":
					c, of, f = newCht(t, false)
				case "bare":
					c, of = opened(t, &tinyFS{body: []byte("x")}, "/file.txt", false)
				}
				var buf bytes.Buffer
				c.srv.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
				of.share.timePolicy = mode.p
				want := mode.want()
				if got := setBasic(t, c, of, tc.in); got != want.status {
					t.Fatalf("status %#x, want %#x", got, want.status)
				}
				if f != nil && want.applied != f.m.Equal(t2) {
					t.Errorf("write time applied = %v, want %v (mtime %v)", f.m.Equal(t2), want.applied, f.m)
				}
				var fields []string
				if buf.Len() > 0 {
					var rec struct {
						Share, Path string
						Fields      []string
					}
					if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
						t.Fatalf("the log line is not one JSON record: %v\n%s", err, buf.Bytes())
					}
					if rec.Share != `"disk"` || rec.Path != `"/file.txt"` {
						t.Errorf("log names share %s path %s", rec.Share, rec.Path)
					}
					fields = rec.Fields
				}
				if !slices.Equal(fields, want.logged) {
					t.Errorf("logged %v, want %v", fields, want.logged)
				}
			})
		}
	}
}

// The path in the log line is the client's. A newline, a quote or an escape in
// it must stay inside the one value.
func TestTimePolicyLogCannotBeForged(t *testing.T) {
	c, of, _ := newCht(t, true)
	var buf bytes.Buffer
	c.srv.Logger = slog.New(slog.NewTextHandler(&buf, nil))
	of.share.timePolicy = TimesLog
	of.path = "/a\nlevel=ERROR msg=forged\x1b[31m\"é"
	if got := setBasic(t, c, of, basic(ft(t0), 0, 0, 0)); got != statusSuccess {
		t.Fatalf("status %#x", got)
	}
	out := buf.String()
	if n := strings.Count(out, "\n"); n != 1 {
		t.Errorf("%d lines in the log, want 1:\n%q", n, out)
	}
	if strings.Contains(out, "\x1b") || !strings.Contains(out, `\\n`) {
		t.Errorf("the path was not escaped: %q", out)
	}
}

func TestTimePolicyZeroValueIsIgnore(t *testing.T) {
	var p TimePolicy
	if p != TimesIgnore {
		t.Fatal("the zero TimePolicy is not the documented default")
	}
	srv := New()
	if err := srv.Share("d", &tinyFS{}, UnstorableTimes(TimesRefuse)); err != nil {
		t.Fatal(err)
	}
	if srv.shareByName("d").timePolicy != TimesRefuse {
		t.Error("UnstorableTimes did not set the policy")
	}
	if err := srv.Share("e", &tinyFS{}); err != nil {
		t.Fatal(err)
	}
	if srv.shareByName("e").timePolicy != TimesIgnore {
		t.Error("a share with no option is not TimesIgnore")
	}
}
