package smb

import (
	"encoding/binary"
	"runtime"
	"testing"
)

// allocated runs f and returns the bytes it allocated.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// The whole-file fallback (tinyFS has neither positional writes nor Truncate)
// materialises the file at the size the client names. Before the bounds, each
// of these one-request inputs was a make() sized by the client: 2^62 a runtime
// panic, 2^38 an allocation that took the server down, a negative size a
// slice panic.
func TestTheWholeFileFallbackRefusesWhatAClientCannotHave(t *testing.T) {
	fs := &tinyFS{body: []byte("hello")}
	c, of := opened(t, fs, "/file.txt", false)

	write := func(off uint64) uint32 {
		body := make([]byte, 48+1)
		binary.LittleEndian.PutUint16(body[2:], uint16(headerLen+48))
		binary.LittleEndian.PutUint32(body[4:], 1)
		binary.LittleEndian.PutUint64(body[8:], off)
		copy(body[16:], of.id[:])
		return statusOf(t, mustDispatch(t, c, cmdWrite, body))
	}
	setEOF := func(size uint64) uint32 {
		in := binary.LittleEndian.AppendUint64(nil, size)
		body := make([]byte, 32)
		body[2], body[3] = infoTypeFile, fileEndOfFileInformation
		binary.LittleEndian.PutUint32(body[4:], uint32(len(in)))
		binary.LittleEndian.PutUint16(body[8:], uint16(headerLen+32))
		copy(body[16:], of.id[:])
		return statusOf(t, mustDispatch(t, c, cmdSetInfo, append(body, in...)))
	}

	cases := []struct {
		name string
		do   func() uint32
		want uint32
	}{
		{"WRITE at 2^62", func() uint32 { return write(1 << 62) }, statusDiskFull},
		{"WRITE at 2^38", func() uint32 { return write(1 << 38) }, statusDiskFull},
		{"WRITE at a negative offset", func() uint32 { return write(1 << 63) }, statusInvalidParameter},
		{"WRITE whose end passes 2^63", func() uint32 { return write(1<<63 - 1) }, statusInvalidParameter},
		{"end-of-file 2^38", func() uint32 { return setEOF(1 << 38) }, statusDiskFull},
		{"end-of-file 1 GiB + 1", func() uint32 { return setEOF(fallbackMaxSize + 1) }, statusDiskFull},
		{"end-of-file negative", func() uint32 { return setEOF(1 << 63) }, statusInvalidParameter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got uint32
			grew := allocated(func() { got = tc.do() })
			if got != tc.want {
				t.Fatalf("status %#x, want %#x", got, tc.want)
			}
			if grew > 1<<20 {
				t.Fatalf("allocated %d bytes before refusing", grew)
			}
		})
	}
	if string(fs.body) != "hello" {
		t.Fatalf("a refused request changed the file: %q", fs.body)
	}

	// The bound is the limit, not below it: growing by exactly
	// fallbackMaxGrowth is served, one byte more is not.
	if st := setEOF(uint64(len(fs.body)) + fallbackMaxGrowth); st != statusSuccess {
		t.Fatalf("growing by exactly the bound answered %#x", st)
	}
	if st := setEOF(uint64(len(fs.body)) + fallbackMaxGrowth + 1); st != statusDiskFull {
		t.Fatalf("one byte past the bound answered %#x", st)
	}
}

// Shrinking is never refused, however large the file already is.
func TestFallbackGrowthNeverRefusesAShrink(t *testing.T) {
	if err := fallbackGrowth(fallbackMaxSize*2, 10); err != nil {
		t.Fatalf("a shrink was refused: %v", err)
	}
	if err := fallbackGrowth(fallbackMaxSize, fallbackMaxSize+1); err == nil {
		t.Fatal("growth past the size bound was allowed")
	}
}
