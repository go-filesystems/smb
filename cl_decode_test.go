package smb

import (
	"encoding/binary"
	"testing"
)

// Every response decoder of the client engine reads bytes a hostile server
// chose. Each one has a fuzz target (the corpus is committed under
// testdata/fuzz) whose invariant is stronger than "does not panic": what it
// returns must lie inside what it was given and inside what was asked for.

func clMsg(structSize uint16, n int) []byte {
	m := make([]byte, headerLen+n)
	copy(m, protocolID[:])
	binary.LittleEndian.PutUint16(m[offStructSize:], headerLen)
	binary.LittleEndian.PutUint16(m[headerLen:], structSize)
	return m
}

func FuzzClientParseHeaderAndBodies(f *testing.F) {
	f.Add(clMsg(89, 88))
	f.Add(clMsg(65, 64))
	f.Add(clMsg(9, 16))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, msg []byte) {
		if _, err := parseCreateResp(msg); err == nil && len(msg) < headerLen+88 {
			t.Fatalf("a CREATE response of %d bytes was accepted", len(msg))
		}
		parseNegotiateResp(msg)
		parseSessionSetupResp(msg)
		parseTreeConnectResp(msg)
		parseWriteResp(msg)
		if b, err := parseInfoResp(msg); err == nil && len(b) > len(msg) {
			t.Fatal("info buffer outside the message")
		}
	})
}

func FuzzClientParseReadResp(f *testing.F) {
	f.Add(clMsg(17, 16), uint32(4096))
	f.Fuzz(func(t *testing.T, msg []byte, want uint32) {
		if d, err := parseReadResp(msg, want); err == nil && (uint32(len(d)) > want || len(d) > len(msg)) {
			t.Fatalf("a READ of %d bytes answered a request for %d", len(d), want)
		}
	})
}

func FuzzClientParseDirEntries(f *testing.F) {
	e := make([]byte, 64+4)
	binary.LittleEndian.PutUint32(e[60:], 4)
	f.Add(e)
	f.Fuzz(func(t *testing.T, b []byte) {
		es, err := parseDirEntries(b)
		if err == nil && len(es) > len(b)/64+1 {
			t.Fatalf("%d entries out of %d bytes", len(es), len(b))
		}
	})
}

func FuzzClientParseServerContexts(f *testing.F) {
	f.Add(clMsg(65, 64), 128, 2)
	f.Fuzz(func(t *testing.T, msg []byte, off, count int) {
		parseServerContexts(msg, off, count)
	})
}

func FuzzClientParseChallenge(f *testing.F) {
	f.Add(append([]byte("NTLMSSP\x00\x02\x00\x00\x00"), make([]byte, 48)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := parseChallenge(b)
		if err != nil {
			return
		}
		if _, _, err := avPairs(c.targetInfo); err == nil {
			n := newCLNTLM("u", "p", "", "cifs/h")
			n.type1()
			n.authenticate(b, c)
		}
	})
}

func FuzzClientParseFullSize(f *testing.F) {
	f.Add(make([]byte, 32))
	f.Fuzz(func(t *testing.T, b []byte) { parseFullSize(b) })
}

func FuzzClientPath(f *testing.F) {
	f.Add("a/b/c")
	f.Fuzz(func(t *testing.T, p string) {
		out, err := clPath(p)
		if err != nil {
			return
		}
		for _, r := range out {
			if r == 0 || r == '/' {
				t.Fatalf("%q came out as %q", p, out)
			}
		}
	})
}

func TestClientPathRefusals(t *testing.T) {
	for _, p := range []string{"../x", "a/../b", "a\\b", "a\x00b"} {
		if _, err := clPath(p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
	if got, err := clPath("a//b/"); err != nil || got != `a\b` {
		t.Errorf("got %q %v", got, err)
	}
	if got, err := clPath(""); err != nil || got != "" {
		t.Errorf("root: %q %v", got, err)
	}
}

func TestClientDirWalkRefusals(t *testing.T) {
	mk := func(next, nl uint32, total int) []byte {
		b := make([]byte, total)
		binary.LittleEndian.PutUint32(b[0:], next)
		binary.LittleEndian.PutUint32(b[60:], nl)
		return b
	}
	for name, b := range map[string][]byte{
		"empty":           nil,
		"short":           make([]byte, 63),
		"odd name":        mk(0, 3, 70),
		"name past end":   mk(0, 10, 70),
		"next backwards":  mk(10, 2, 70),
		"next past end":   mk(200, 2, 70),
		"next in name":    mk(65, 4, 80),
		"truncated chain": mk(68, 4, 70),
	} {
		if _, err := parseDirEntries(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if es, err := parseDirEntries(mk(0, 2, 66)); err != nil || len(es) != 1 {
		t.Errorf("one entry: %v %v", es, err)
	}
}

func TestClientReadRespNeverExceedsTheRequest(t *testing.T) {
	m := clMsg(17, 16+8)
	m[headerLen+2] = headerLen + 16
	binary.LittleEndian.PutUint32(m[headerLen+4:], 8)
	if _, err := parseReadResp(m, 4); err == nil {
		t.Fatal("8 bytes accepted for a request of 4")
	}
	if d, err := parseReadResp(m, 8); err != nil || len(d) != 8 {
		t.Fatalf("%v %v", d, err)
	}
}
