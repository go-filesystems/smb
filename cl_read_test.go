package smb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

// The pipelined read path: ReadAt cuts a large buffer into pieces read
// concurrently, WriteTo streams the file with a window of READs in flight.
// The fake server's MaxReadSize is 64 KiB, so a piece is 64 KiB.

const rdPiece = 1 << 16

func rdData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

// rdServer serves data, answering at most max bytes per READ when max > 0, and
// the failure status failAt (when failAt > 0) for any READ at or past that
// offset. It counts the READs it saw.
func rdServer(t *testing.T, data []byte, max int, failAt uint64, reads *atomic.Int64) *ClientShare {
	t.Helper()
	_, s := newFake(t, func(r fkReq) (uint32, []byte) {
		switch r.cmd {
		case cmdCreate:
			return stOK, fkCreate(0x20, uint64(len(data)), 1)
		case cmdRead:
			off, n := binary.LittleEndian.Uint64(r.body[8:]), binary.LittleEndian.Uint32(r.body[4:])
			reads.Add(1)
			if failAt > 0 && off >= failAt {
				return 0xC0000185, fkBody(9, 9) // STATUS_IO_DEVICE_ERROR
			}
			if off >= uint64(len(data)) {
				return stEOF, fkBody(9, 9)
			}
			end := min(off+uint64(n), uint64(len(data)))
			if max > 0 {
				end = min(end, off+uint64(max))
			}
			return stOK, fkRead(data[off:end])
		}
		return stOK, fkBody(60, 60)
	})
	return s
}

func rdOpen(t *testing.T, data []byte, max int, failAt uint64) (*ClientFile, *atomic.Int64) {
	t.Helper()
	var reads atomic.Int64
	f, err := rdServer(t, data, max, failAt, &reads).Open(ctx0, "a")
	if err != nil {
		t.Fatal(err)
	}
	return f, &reads
}

func TestClientReadAtPipelinesAcrossPieces(t *testing.T) {
	defer recovered(t)
	data := rdData(3*rdPiece + 1234)
	for name, max := range map[string]int{"whole pieces": 0, "short answers": rdPiece/2 + 3} {
		f, reads := rdOpen(t, data, max, 0)
		p := make([]byte, len(data))
		if n, err := f.ReadAt(p, 0); n != len(data) || err != nil || !bytes.Equal(p, data) {
			t.Fatalf("%s: %d %v", name, n, err)
		}
		if max > 0 && reads.Load() < 7 {
			t.Errorf("%s: %d READs for a server that answers half pieces", name, reads.Load())
		}
		// inside the file, not aligned to a piece
		mid := make([]byte, 2*rdPiece+10)
		if n, err := f.ReadAt(mid, 100); n != len(mid) || err != nil || !bytes.Equal(mid, data[100:100+len(mid)]) {
			t.Fatalf("%s: mid %d %v", name, n, err)
		}
		// past the end: the bytes there are, then io.EOF
		over := make([]byte, len(data)+70000)
		if n, err := f.ReadAt(over, 0); n != len(data) || err != io.EOF || !bytes.Equal(over[:n], data) {
			t.Fatalf("%s: past the end %d %v", name, n, err)
		}
		// a file ending exactly on a piece boundary
		if n, err := f.ReadAt(make([]byte, rdPiece), int64(3*rdPiece)); n != 1234 || err != io.EOF {
			t.Fatalf("%s: tail %d %v", name, n, err)
		}
		if n, err := f.ReadAt(nil, 0); n != 0 || err != nil {
			t.Fatalf("%s: empty %d %v", name, n, err)
		}
	}
}

func TestClientReadAtReportsTheFirstFailedPiece(t *testing.T) {
	defer recovered(t)
	data := rdData(5 * rdPiece)
	f, _ := rdOpen(t, data, 0, 2*rdPiece)
	p := make([]byte, len(data))
	n, err := f.ReadAt(p, 0)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 0xC0000185 || n != 2*rdPiece || !bytes.Equal(p[:n], data[:n]) {
		t.Fatalf("%d %v", n, err)
	}
}

func TestClientWriteToStreamsTheRest(t *testing.T) {
	defer recovered(t)
	for name, size := range map[string]int{
		"several pieces and a tail": 6*rdPiece + 99,
		"exact pieces":              4 * rdPiece,
		"under one piece":           777,
		"more than the window":      9 * rdPiece,
		"empty":                     0,
	} {
		for mname, max := range map[string]int{"whole": 0, "short": rdPiece/3 + 1} {
			data := rdData(size)
			f, _ := rdOpen(t, data, max, 0)
			var out bytes.Buffer
			n, err := f.WriteTo(&out)
			if err != nil || n != int64(size) || !bytes.Equal(out.Bytes(), data) {
				t.Fatalf("%s/%s: %d %v", name, mname, n, err)
			}
			if f.off != int64(size) {
				t.Errorf("%s/%s: the offset is %d", name, mname, f.off)
			}
		}
	}
}

func TestClientWriteToStartsAtTheOffset(t *testing.T) {
	defer recovered(t)
	data := rdData(3*rdPiece + 5)
	f, _ := rdOpen(t, data, 0, 0)
	head := make([]byte, 100)
	if n, err := f.Read(head); n != 100 || err != nil {
		t.Fatalf("%d %v", n, err)
	}
	var out bytes.Buffer
	if n, err := f.WriteTo(&out); err != nil || n != int64(len(data)-100) || !bytes.Equal(out.Bytes(), data[100:]) {
		t.Fatalf("%d %v", n, err)
	}
	// io.Copy takes this path
	g, _ := rdOpen(t, data, 0, 0)
	var viaCopy bytes.Buffer
	if n, err := io.Copy(&viaCopy, g); err != nil || n != int64(len(data)) || !bytes.Equal(viaCopy.Bytes(), data) {
		t.Fatalf("io.Copy: %d %v", n, err)
	}
}

type rdWriter struct {
	mu    sync.Mutex
	limit int // bytes accepted before the failure
	got   int
	short bool // fail by a short count with no error
	err   error
}

func (w *rdWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	room := w.limit - w.got
	if len(p) <= room {
		w.got += len(p)
		return len(p), nil
	}
	w.got += room
	if w.short {
		return room, nil
	}
	return room, w.err
}

func TestClientWriteToStopsOnWriterAndServerFailures(t *testing.T) {
	defer recovered(t)
	data := rdData(6 * rdPiece)
	boom := errors.New("disk full")

	f, _ := rdOpen(t, data, 0, 0)
	w := &rdWriter{limit: rdPiece + 10, err: boom}
	if n, err := f.WriteTo(w); !errors.Is(err, boom) || n != int64(rdPiece+10) {
		t.Fatalf("a writer error: %d %v", n, err)
	}
	if f.off != int64(rdPiece+10) {
		t.Errorf("the offset moved by what was written: %d", f.off)
	}

	f, _ = rdOpen(t, data, 0, 0)
	w = &rdWriter{limit: 5, short: true}
	if n, err := f.WriteTo(w); !errors.Is(err, io.ErrShortWrite) || n != 5 {
		t.Fatalf("a short write: %d %v", n, err)
	}

	// the pieces before a failed one are still written, in order
	f, _ = rdOpen(t, data, 0, 3*rdPiece)
	var out bytes.Buffer
	n, err := f.WriteTo(&out)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 0xC0000185 || n != 3*rdPiece || !bytes.Equal(out.Bytes(), data[:n]) {
		t.Fatalf("a server error: %d %v", n, err)
	}
}

func TestClientChunkFollowsTheNegotiatedMaxRead(t *testing.T) {
	f := &ClientFile{s: &ClientShare{c: &ClientConn{}}}
	if got := f.chunk(); got != clReadChunk {
		t.Errorf("no maxRead: %d", got)
	}
	f.s.c.maxRead = 4096
	if got := f.chunk(); got != 4096 {
		t.Errorf("small maxRead: %d", got)
	}
	f.s.c.maxRead = 8 << 20
	if got := f.chunk(); got != clReadChunk {
		t.Errorf("large maxRead: %d", got)
	}
}

// A READ answered in full is handed back as it came: no copy of the piece.
func TestClientFetchDoesNotCopyAWholeAnswer(t *testing.T) {
	defer recovered(t)
	data := rdData(rdPiece)
	f, _ := rdOpen(t, data, 0, 0)
	whole := testing.AllocsPerRun(5, func() { f.fetch(ctx0, 0, rdPiece) })
	f2, _ := rdOpen(t, data, rdPiece/2, 0)
	halves := testing.AllocsPerRun(5, func() { f2.fetch(ctx0, 0, rdPiece) })
	if whole >= halves {
		t.Errorf("a whole answer costs %v allocations, two halves %v", whole, halves)
	}
	got, err := f.fetch(ctx0, 0, rdPiece)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("%d %v", len(got), err)
	}
}

func TestClientReadFrameBulkAllocatesOnceAndKeepsTheBound(t *testing.T) {
	body := rdData(300 << 10)
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	frame = append(frame, body...)

	got, err := readFrameBulk(bytes.NewReader(frame), 1<<20)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("%d %v", len(got), err)
	}
	if cap(got) < len(body)+frameTagRoom {
		t.Errorf("cap %d: no room for the tag a decrypt appends", cap(got))
	}
	// the length the header announces is not trusted past the bound
	if _, err := readFrameBulk(bytes.NewReader(frame), len(body)-1); err == nil {
		t.Error("a frame over the bound was read")
	}
	// the plain reader still starts small and follows the bytes that arrive
	small, err := readFrameMax(bytes.NewReader(frame), 1<<20)
	if err != nil || !bytes.Equal(small, body) {
		t.Fatalf("%d %v", len(small), err)
	}
	bulk := testing.AllocsPerRun(5, func() { readFrameBulk(bytes.NewReader(frame), 1<<20) })
	grow := testing.AllocsPerRun(5, func() { readFrameMax(bytes.NewReader(frame), 1<<20) })
	if bulk >= grow {
		t.Errorf("bulk allocates %v times, the doubling reader %v", bulk, grow)
	}
	// a frame cut short is an error whichever reader is used
	if _, err := readFrameBulk(bytes.NewReader(frame[:1000]), 1<<20); err == nil {
		t.Error("a truncated frame")
	}
}

func TestClientBufferFreelist(t *testing.T) {
	drain := func() {
		for {
			select {
			case <-clBufs:
			default:
				return
			}
		}
	}
	drain()
	defer drain()

	b := getBuf(100)
	if len(b) != 0 || cap(b) < 100 {
		t.Fatalf("len %d cap %d", len(b), cap(b))
	}
	b = append(b, 1, 2, 3)
	putBuf(b)
	if again := getBuf(50); len(again) != 0 || &again[:1][0] != &b[:1][0] {
		t.Error("a returned buffer was not reused")
	}
	// too small for the request: a new one, and the small one is not lost
	putBuf(make([]byte, 0, 10))
	if big := getBuf(1000); cap(big) < 1000 {
		t.Errorf("cap %d", cap(big))
	}
	// nothing worth keeping
	drain()
	putBuf(nil)
	putBuf(make([]byte, 0, clBufMax+1))
	if len(clBufs) != 0 {
		t.Errorf("%d buffers kept that should not be", len(clBufs))
	}
	// a full freelist drops the extra one instead of blocking
	for range cap(clBufs) + 3 {
		putBuf(make([]byte, 0, 8))
	}
	if len(clBufs) != cap(clBufs) {
		t.Errorf("%d buffers kept", len(clBufs))
	}
}
