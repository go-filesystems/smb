package smb

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// A scripted server for the operations: the connection is already past the
// session (signing on, zero key), and each request is answered by a function
// that picks the status and the body, so every response a hostile or broken
// server could send reaches the operation that has to cope with it.

const (
	fkDrop       = 0xFFFFFFFF // as a status: close the connection instead of answering
	fkBadCommand = 0xFFFFFFFE // as a status: answer with another command
)

type fkReq struct {
	cmd  command
	body []byte // after the 64-byte header
}

type fkAnswer func(r fkReq) (status uint32, body []byte)

func newFake(t *testing.T, answer fkAnswer) (*ClientConn, *ClientShare) {
	t.Helper()
	cn, sn := net.Pipe()
	c := &ClientConn{nc: cn, o: ClientOptions{User: "u", Host: "h"}, credits: 64, pending: map[uint64]*clPending{},
		done: make(chan struct{}), sid: 7, sigAlg: sigCMAC, signKey: make([]byte, 16), ready: true,
		maxTrans: 1 << 20, maxRead: 1 << 16, maxWrite: 1 << 16}
	c.cond = sync.NewCond(&c.mu)
	c.frameMax.Store(clChunk + 4096)
	go c.readLoop()
	go func() {
		defer sn.Close()
		for {
			frame, err := readFrameMax(sn, 1<<22)
			if err != nil {
				return
			}
			h, err := parseHeader(frame)
			if err != nil {
				return
			}
			status, body := answer(fkReq{h.command, frame[headerLen:]})
			if status == fkDrop {
				return
			}
			cmd := h.command
			if status == fkBadCommand { // answer with the next command: a protocol violation
				status, cmd = stOK, h.command+1
			}
			m := make([]byte, headerLen, headerLen+len(body))
			copy(m, protocolID[:])
			binary.LittleEndian.PutUint16(m[offStructSize:], headerLen)
			binary.LittleEndian.PutUint32(m[offStatus:], status)
			binary.LittleEndian.PutUint16(m[offCommand:], uint16(cmd))
			binary.LittleEndian.PutUint16(m[offCredits:], 32)
			binary.LittleEndian.PutUint32(m[offFlags:], flagServerToRedir|flagSigned)
			binary.LittleEndian.PutUint64(m[offMessageID:], h.messageID)
			binary.LittleEndian.PutUint32(m[offTreeID:], h.treeID)
			binary.LittleEndian.PutUint64(m[offSessionID:], 7)
			m = append(m, body...)
			signMessage(sigCMAC, c.signKey, m)
			out := binary.BigEndian.AppendUint32(nil, uint32(len(m)))
			if _, err := sn.Write(append(out, m...)); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { c.Close() })
	return c, &ClientShare{c: c, tid: 9, name: "s"}
}

var ctx0 = context.Background()

// fkBody builds a response body of structure size ss and n bytes.
func fkBody(ss uint16, n int) []byte {
	b := make([]byte, n)
	binary.LittleEndian.PutUint16(b, ss)
	return b
}

func fkCreate(attrs uint32, eof uint64, id byte) []byte {
	b := fkBody(89, 88)
	binary.LittleEndian.PutUint64(b[48:], eof)
	binary.LittleEndian.PutUint32(b[56:], attrs)
	b[64] = id
	return b
}

func fkInfo(data []byte) []byte {
	b := fkBody(9, 8)
	binary.LittleEndian.PutUint16(b[2:], headerLen+8)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(data)))
	return append(b, data...)
}

func fkRead(data []byte) []byte {
	b := fkBody(17, 16)
	b[2] = headerLen + 16
	binary.LittleEndian.PutUint32(b[4:], uint32(len(data)))
	return append(b, data...)
}

func fkWrite(n uint32) []byte {
	b := fkBody(17, 16)
	binary.LittleEndian.PutUint32(b[4:], n)
	return b
}

func fkTree(flags uint32) []byte {
	b := fkBody(16, 16)
	binary.LittleEndian.PutUint32(b[4:], flags)
	return b
}

const (
	stOK       = uint32(statusSuccess)
	stDenied   = 0xC0000022
	stNoMore   = uint32(statusNoMoreFiles)
	stEOF      = uint32(statusEndOfFile)
	stNotFound = 0xC0000034
)

// fkFail answers cmd with status st and every other command with success and
// a plausible body.
func fkFail(cmd command, st uint32) fkAnswer {
	return func(r fkReq) (uint32, []byte) {
		if r.cmd == cmd {
			return st, fkBody(9, 9)
		}
		switch r.cmd {
		case cmdCreate:
			return stOK, fkCreate(0x20, 5, 1)
		case cmdQueryInfo:
			return stOK, fkInfo(make([]byte, 32))
		case cmdQueryDirectory:
			return stOK, fkInfo(clDirRec("a", 0, 1, 0x20))
		case cmdWrite:
			return stOK, fkWrite(3)
		case cmdRead:
			return stOK, fkRead([]byte("abc"))
		}
		return stOK, fkBody(60, 60)
	}
}

// transportErr is an error that came from the connection, not from a decoder
// or a status: the guard that returns it is the one that was tested.
func transportErr(err error) bool {
	var se *StatusError
	return err != nil && !errors.As(err, &se) && !errors.Is(err, errShort) && !errors.Is(err, errBadField) && !errors.Is(err, errClientEmptyBatch)
}

func wantStatus(t *testing.T, name string, err error, cmd string, st uint32) {
	t.Helper()
	var se *StatusError
	if !errors.As(err, &se) || se.Status != st || se.Command != cmd {
		t.Errorf("%s: %v, want status %#x on %s", name, err, st, cmd)
	}
}

func TestClientOpsReportEachFailureAsItself(t *testing.T) {
	type op struct {
		name string
		run  func(s *ClientShare) error
		cmd  command
		opn  string
	}
	ops := []op{
		{"Stat/CREATE", func(s *ClientShare) error { _, err := s.Stat(ctx0, "a"); return err }, cmdCreate, "CREATE"},
		{"Stat/CLOSE", func(s *ClientShare) error { _, err := s.Stat(ctx0, "a"); return err }, cmdClose, "CLOSE"},
		{"ReadDir/CREATE", func(s *ClientShare) error { _, err := s.ReadDir(ctx0, "d"); return err }, cmdCreate, "CREATE"},
		{"ReadDir/QUERY_DIRECTORY", func(s *ClientShare) error { _, err := s.ReadDir(ctx0, "d"); return err }, cmdQueryDirectory, "QUERY_DIRECTORY"},
		{"Statfs/CREATE", func(s *ClientShare) error { _, err := s.Statfs(ctx0); return err }, cmdCreate, "CREATE"},
		{"Statfs/QUERY_INFO", func(s *ClientShare) error { _, err := s.Statfs(ctx0); return err }, cmdQueryInfo, "QUERY_INFO"},
		{"Open/CREATE", func(s *ClientShare) error { _, err := s.Open(ctx0, "a"); return err }, cmdCreate, "CREATE"},
		{"WriteFile/CREATE", func(s *ClientShare) error { return s.WriteFile(ctx0, "a", []byte("abc")) }, cmdCreate, "CREATE"},
		{"WriteFile/WRITE", func(s *ClientShare) error { return s.WriteFile(ctx0, "a", []byte("abc")) }, cmdWrite, "WRITE"},
		{"Remove/CREATE", func(s *ClientShare) error { return s.Remove(ctx0, "a") }, cmdCreate, "CREATE"},
		{"Remove/CLOSE", func(s *ClientShare) error { return s.Remove(ctx0, "a") }, cmdClose, "CLOSE"},
		{"ReadAt/READ", func(s *ClientShare) error {
			f, err := s.Open(ctx0, "a")
			if err != nil {
				return err
			}
			_, err = f.ReadAt(make([]byte, 3), 0)
			return err
		}, cmdRead, "READ"},
	}
	for _, o := range ops {
		_, s := newFake(t, fkFail(o.cmd, stDenied))
		wantStatus(t, o.name+" status", o.run(s), o.opn, stDenied)
		_, s = newFake(t, fkFail(o.cmd, fkDrop))
		if err := o.run(s); !transportErr(err) {
			t.Errorf("%s dropped: %v", o.name, err)
		}
		// a success whose body is too short to decode is a decoding error, not a pass
		if o.cmd == cmdClose {
			continue
		}
		short := func(r fkReq) (uint32, []byte) {
			st, b := fkFail(99, 0)(r)
			if r.cmd == o.cmd {
				return st, nil
			}
			return st, b
		}
		_, s = newFake(t, short)
		if err := o.run(s); err == nil || transportErr(err) {
			t.Errorf("%s short body: %v", o.name, err)
		}
	}
}

func TestClientStatReturnsWhatWasOpened(t *testing.T) {
	_, s := newFake(t, func(r fkReq) (uint32, []byte) {
		if r.cmd == cmdCreate {
			return stOK, fkCreate(0x10, 1<<63, 1)
		}
		return stOK, fkBody(60, 60)
	})
	i, err := s.Stat(ctx0, "dir")
	if err != nil || i.Name != "dir" || !i.IsDir() || i.Size != 1<<62 {
		t.Fatalf("%+v %v", i, err)
	}
}

func TestClientReadDirWalk(t *testing.T) {
	dots := func(extra ...string) []byte {
		var out []byte
		names := append([]string{".", ".."}, extra...)
		for i, n := range names {
			e := clDirRec(n, 0, uint64(i), 0x20)
			if i < len(names)-1 {
				for len(e)%8 != 0 {
					e = append(e, 0)
				}
				binary.LittleEndian.PutUint32(e, uint32(len(e)))
			}
			out = append(out, e...)
		}
		return out
	}
	script := func(batches ...[]byte) fkAnswer {
		i := 0
		return func(r fkReq) (uint32, []byte) {
			switch r.cmd {
			case cmdCreate:
				return stOK, fkCreate(0x10, 0, 1)
			case cmdQueryDirectory:
				if i == 0 && r.body[3]&1 == 0 || i > 0 && r.body[3]&1 != 0 {
					t.Errorf("batch %d: restart flag %#x", i, r.body[3])
				}
				if i >= len(batches) {
					return stNoMore, fkBody(9, 9)
				}
				i++
				return stOK, fkInfo(batches[i-1])
			}
			return stOK, fkBody(60, 60)
		}
	}
	// a first batch of dots only, then a batch with entries, then the end
	_, s := newFake(t, script(dots(), dots("x")))
	es, err := s.ReadDir(ctx0, "d")
	if err != nil || len(es) != 1 || es[0].Name != "x" {
		t.Fatalf("%+v %v", es, err)
	}
	// an empty directory: dots, then the end
	_, s = newFake(t, script(dots()))
	if es, err := s.ReadDir(ctx0, "d"); err != nil || len(es) != 0 {
		t.Fatalf("%+v %v", es, err)
	}
	// the end at once
	_, s = newFake(t, script())
	if es, err := s.ReadDir(ctx0, "d"); err != nil || len(es) != 0 {
		t.Fatalf("%+v %v", es, err)
	}
	// a broken list
	_, s = newFake(t, script(clDirRec("x", 0, 0, 0)[:30]))
	if _, err := s.ReadDir(ctx0, "d"); !errors.Is(err, errBadField) && !errors.Is(err, errShort) {
		t.Fatalf("a truncated entry: %v", err)
	}
	_, s = newFake(t, script([]byte{}))
	if _, err := s.ReadDir(ctx0, "d"); err == nil {
		t.Fatal("an empty buffer was a listing")
	}
}

func TestClientReadDirIsBounded(t *testing.T) {
	// a server that answers success forever with dots only never ends the
	// listing on its own: the client has to
	calls := 0
	_, s := newFake(t, func(r fkReq) (uint32, []byte) {
		switch r.cmd {
		case cmdCreate:
			return stOK, fkCreate(0x10, 0, 1)
		case cmdQueryDirectory:
			calls++
			return stOK, fkInfo(clDirRec(".", 0, 0, 0x10))
		}
		return stOK, fkBody(60, 60)
	})
	done := make(chan error, 1)
	go func() { _, err := s.ReadDir(ctx0, "d"); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, errClientEmptyBatch) {
			t.Fatalf("%v", err)
		}
		if calls != clMaxIdleBatches+1 {
			t.Fatalf("%d QUERY_DIRECTORY before giving up, want %d", calls, clMaxIdleBatches+1)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ReadDir does not end against a server that never says NO_MORE_FILES")
	}
}

func TestClientReadDirEntryCap(t *testing.T) {
	old := clMaxDirEntries
	clMaxDirEntries = 3
	defer func() { clMaxDirEntries = old }()
	batch := func(n int) []byte {
		var out []byte
		for i := 0; i < n; i++ {
			e := clDirRec("n", 0, 0, 0x20)
			for len(e)%8 != 0 {
				e = append(e, 0)
			}
			if i < n-1 {
				binary.LittleEndian.PutUint32(e, uint32(len(e)))
			}
			out = append(out, e...)
		}
		return out
	}
	for n, ok := range map[int]bool{3: true, 4: false} {
		sent := false
		_, s := newFake(t, func(r fkReq) (uint32, []byte) {
			switch r.cmd {
			case cmdCreate:
				return stOK, fkCreate(0x10, 0, 1)
			case cmdQueryDirectory:
				if sent {
					return stNoMore, fkBody(9, 9)
				}
				sent = true
				return stOK, fkInfo(batch(n))
			}
			return stOK, fkBody(60, 60)
		})
		es, err := s.ReadDir(ctx0, "d")
		if ok && (err != nil || len(es) != 3) {
			t.Errorf("%d entries: %v %v", n, len(es), err)
		}
		if !ok && err == nil {
			t.Errorf("%d entries: accepted", n)
		}
	}
}

func TestClientStatfs(t *testing.T) {
	_, s := newFake(t, func(r fkReq) (uint32, []byte) {
		switch r.cmd {
		case cmdCreate:
			return stOK, fkCreate(0x10, 0, 1)
		case cmdQueryInfo:
			b := make([]byte, 32)
			binary.LittleEndian.PutUint64(b[0:], 100)
			binary.LittleEndian.PutUint64(b[8:], 40)
			binary.LittleEndian.PutUint64(b[16:], 50)
			binary.LittleEndian.PutUint32(b[24:], 8)
			binary.LittleEndian.PutUint32(b[28:], 512)
			return stOK, fkInfo(b)
		}
		return stOK, fkBody(60, 60)
	})
	f, err := s.Statfs(ctx0)
	if err != nil || f != (ClientFsInfo{Unit: 4096, Total: 100, Free: 50, Avail: 40}) {
		t.Fatalf("%+v %v", f, err)
	}
	for name, data := range map[string][]byte{"31 bytes": make([]byte, 31), "no buffer": nil} {
		_, s := newFake(t, func(r fkReq) (uint32, []byte) {
			switch r.cmd {
			case cmdCreate:
				return stOK, fkCreate(0x10, 0, 1)
			case cmdQueryInfo:
				return stOK, fkInfo(data)
			}
			return stOK, fkBody(60, 60)
		})
		if _, err := s.Statfs(ctx0); !errors.Is(err, errShort) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a buffer that points outside the message
	_, s = newFake(t, func(r fkReq) (uint32, []byte) {
		switch r.cmd {
		case cmdCreate:
			return stOK, fkCreate(0x10, 0, 1)
		case cmdQueryInfo:
			b := fkInfo(make([]byte, 4))
			binary.LittleEndian.PutUint32(b[4:], 400)
			return stOK, b
		}
		return stOK, fkBody(60, 60)
	})
	if _, err := s.Statfs(ctx0); !errors.Is(err, errBadField) {
		t.Errorf("a buffer past the end: %v", err)
	}
}

func fkFile(read func(off uint64, n uint32) (uint32, []byte)) fkAnswer {
	return func(r fkReq) (uint32, []byte) {
		switch r.cmd {
		case cmdCreate:
			return stOK, fkCreate(0x20, 10, 1)
		case cmdRead:
			return read(binary.LittleEndian.Uint64(r.body[8:]), binary.LittleEndian.Uint32(r.body[4:]))
		}
		return stOK, fkBody(60, 60)
	}
}

func TestClientReadAt(t *testing.T) {
	data := []byte("0123456789")
	_, s := newFake(t, fkFile(func(off uint64, n uint32) (uint32, []byte) {
		if off >= uint64(len(data)) {
			return stEOF, fkBody(9, 9)
		}
		return stOK, fkRead(data[off:min(off+uint64(n), uint64(len(data)))])
	}))
	f, err := s.Open(ctx0, "a")
	if err != nil || f.Size() != 10 {
		t.Fatalf("%v %v", f, err)
	}
	p := make([]byte, 4)
	if n, err := f.ReadAt(p, 3); n != 4 || err != nil || string(p) != "3456" {
		t.Fatalf("%d %v %q", n, err, p)
	}
	if n, err := f.ReadAt(make([]byte, 20), 0); n != 10 || err != io.EOF {
		t.Fatalf("a read past the end: %d %v", n, err)
	}
	if _, err := f.ReadAt(p, -1); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("a negative offset: %v", err)
	}
	var all []byte
	for {
		n, err := f.Read(p)
		all = append(all, p[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if string(all) != "0123456789" {
		t.Fatalf("sequential read: %q", all)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// success with no data is the end of the file, not a reason to ask again
	asked := 0
	_, s = newFake(t, fkFile(func(off uint64, n uint32) (uint32, []byte) {
		if asked++; asked > 3 { // a client that asks again would never stop
			return fkDrop, nil
		}
		return stOK, fkRead(nil)
	}))
	f, _ = s.Open(ctx0, "a")
	if n, err := f.ReadAt(make([]byte, 5), 0); n != 0 || err != io.EOF || asked != 1 {
		t.Fatalf("%d %v after %d requests", n, err, asked)
	}
	// more than was asked for is a server writing past the buffer
	_, s = newFake(t, fkFile(func(off uint64, n uint32) (uint32, []byte) { return stOK, fkRead(make([]byte, n+1)) }))
	f, _ = s.Open(ctx0, "a")
	if _, err := f.ReadAt(make([]byte, 5), 0); err == nil || !strings.Contains(err.Error(), "6 bytes for a 5-byte read") {
		t.Fatalf("an oversized read: %v", err)
	}
}

func TestClientWriteFile(t *testing.T) {
	var got []byte
	step := uint32(0)
	_, s := newFake(t, func(r fkReq) (uint32, []byte) {
		switch r.cmd {
		case cmdCreate:
			return stOK, fkCreate(0x20, 0, 1)
		case cmdWrite:
			n := binary.LittleEndian.Uint32(r.body[4:])
			if step == 0 || step > n {
				step = n
			}
			got = append(got, r.body[48:48+step]...)
			return stOK, fkWrite(step)
		}
		return stOK, fkBody(60, 60)
	})
	step = 2 // the server takes two bytes at a time
	if err := s.WriteFile(ctx0, "a", []byte("hello")); err != nil || string(got) != "hello" {
		t.Fatalf("%q %v", got, err)
	}
	for name, w := range map[string]func(n uint32) uint32{
		"zero":         func(n uint32) uint32 { return 0 },
		"more than n":  func(n uint32) uint32 { return n + 1 },
		"exactly n":    func(n uint32) uint32 { return n },
		"a single one": func(n uint32) uint32 { return 1 },
	} {
		writes := 0
		_, s := newFake(t, func(r fkReq) (uint32, []byte) {
			switch r.cmd {
			case cmdCreate:
				return stOK, fkCreate(0x20, 0, 1)
			case cmdWrite:
				if writes++; writes > 10 { // a client that asks again would never stop
					return fkDrop, nil
				}
				return stOK, fkWrite(w(binary.LittleEndian.Uint32(r.body[4:])))
			}
			return stOK, fkBody(60, 60)
		})
		err := s.WriteFile(ctx0, "a", []byte("hello"))
		switch name {
		case "zero", "more than n":
			if err == nil || !strings.Contains(err.Error(), "impossible number") {
				t.Errorf("%s: %v", name, err)
			}
		default:
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

func TestClientMount(t *testing.T) {
	var asked int
	c, _ := newFake(t, func(r fkReq) (uint32, []byte) {
		asked++
		return stOK, fkTree(0)
	})
	for _, name := range []string{`a\b`, "a/b", "a\x00b", `\`, "/"} {
		if _, err := c.Mount(ctx0, name); err == nil {
			t.Errorf("share %q accepted", name)
		}
	}
	if asked != 0 {
		t.Fatalf("%d requests for bad names", asked)
	}
	sh, err := c.Mount(ctx0, "data")
	if err != nil || sh.name != "data" || sh.tid != 0 {
		t.Fatalf("%+v %v", sh, err)
	}
	c, _ = newFake(t, func(r fkReq) (uint32, []byte) { return stDenied, fkBody(9, 9) })
	_, err = c.Mount(ctx0, "data")
	wantStatus(t, "denied", err, "TREE_CONNECT", stDenied)
	c, _ = newFake(t, func(r fkReq) (uint32, []byte) { return stOK, nil })
	if _, err = c.Mount(ctx0, "data"); !errors.Is(err, errShort) {
		t.Errorf("short: %v", err)
	}
	c, _ = newFake(t, func(r fkReq) (uint32, []byte) { return fkDrop, nil })
	if _, err = c.Mount(ctx0, "data"); !transportErr(err) {
		t.Errorf("dropped: %v", err)
	}
	// a share that wants encryption on a connection that has no keys
	c, _ = newFake(t, func(r fkReq) (uint32, []byte) { return stOK, fkTree(shareFlagEncryptData) })
	if _, err = c.Mount(ctx0, "data"); !errors.Is(err, ErrEncryptionRequired) {
		t.Errorf("encrypt-data share without keys: %v", err)
	}
	if c.Encrypted() {
		t.Error("the connection switched to encryption with no key")
	}
}

func TestClientDialNeedsAUser(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	go func() { time.Sleep(300 * time.Millisecond); b.Close() }() // a dial that goes on would wait for a server
	if _, err := ClientDial(ctx0, a, ClientOptions{Password: "x"}); err == nil || !strings.Contains(err.Error(), "no user name") {
		t.Fatalf("dialled without a user: %v", err)
	}
}
