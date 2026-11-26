package smb

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// Boundary tests: for each bound a decoder checks, the byte on each side of it.

// recovered turns a panic into a failed assertion: a decoder whose guard is
// gone panics on the short input, and that must read as "the guard was tested",
// with the panic as the message.
func recovered(t *testing.T) {
	if r := recover(); r != nil {
		t.Errorf("panicked: %v", r)
	}
}

func TestClientBodyBounds(t *testing.T) {
	defer recovered(t)
	if _, err := parseTreeConnectResp(clMsg(16, 16)); err != nil {
		t.Fatalf("exact size: %v", err)
	}
	if _, err := parseTreeConnectResp(clMsg(16, 15)); !errors.Is(err, errShort) {
		t.Fatalf("one byte short: %v", err)
	}
	if _, err := parseTreeConnectResp(clMsg(17, 16)); err == nil || errors.Is(err, errShort) {
		t.Fatalf("wrong structure size: %v", err)
	}
	if _, err := parseTreeConnectResp(nil); !errors.Is(err, errShort) {
		t.Fatalf("empty: %v", err)
	}
}

// infoMsg is a response of structure size 9 with the buffer at off, n bytes
// long, in a message total bytes long.
func infoMsg(off, n, total int) []byte {
	m := clMsg(9, total-headerLen)
	binary.LittleEndian.PutUint16(m[headerLen+2:], uint16(off))
	binary.LittleEndian.PutUint32(m[headerLen+4:], uint32(n))
	return m
}

func TestClientBufBounds(t *testing.T) {
	defer recovered(t)
	const min = headerLen + 8
	for name, tc := range map[string]struct {
		off, n, total int
		ok            bool
		empty         bool
	}{
		"fits exactly":          {min, 10, min + 10, true, false},
		"one byte past the end": {min, 11, min + 10, false, false},
		"one byte before first": {min - 1, 4, min + 10, false, false},
		"offset at the end":     {min + 10, 1, min + 10, false, false},
		"offset past the end":   {min + 11, 1, min + 10, false, false},
		"empty, anywhere":       {0, 0, min + 10, true, true},
		"empty, far away":       {60000, 0, min + 10, true, true},
		"last byte":             {min + 9, 1, min + 10, true, false},
	} {
		b, err := parseInfoResp(infoMsg(tc.off, tc.n, tc.total))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v", name, err)
		}
		if tc.ok && (len(b) == 0) != tc.empty {
			t.Errorf("%s: len %d", name, len(b))
		}
		if err != nil && !errors.Is(err, errBadField) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a 32-bit length that wraps nowhere: far larger than the message
	if _, err := parseInfoResp(infoMsg(min, 1<<31, min+10)); err == nil {
		t.Error("a 2 GiB buffer in a 10-byte message")
	}
}

func TestClientNegotiateRespHead(t *testing.T) {
	defer recovered(t)
	if _, err := parseNegotiateResp(clMsg(65, 63)); !errors.Is(err, errShort) {
		t.Fatalf("short: %v", err)
	}
	m := clMsg(65, 64)
	binary.LittleEndian.PutUint16(m[headerLen+2:], 3)
	binary.LittleEndian.PutUint16(m[headerLen+4:], 0x0311)
	binary.LittleEndian.PutUint16(m[headerLen+6:], 3)
	binary.LittleEndian.PutUint32(m[headerLen+24:], 0x11)
	binary.LittleEndian.PutUint32(m[headerLen+28:], 0x21)
	binary.LittleEndian.PutUint32(m[headerLen+32:], 0x31)
	binary.LittleEndian.PutUint32(m[headerLen+36:], 0x41)
	binary.LittleEndian.PutUint32(m[headerLen+60:], 0x80)
	n, err := parseNegotiateResp(m)
	if err != nil {
		t.Fatal(err)
	}
	if n.secMode != 3 || n.dialect != 0x0311 || n.ctxCount != 3 || n.caps != 0x11 || n.maxTrans != 0x21 ||
		n.maxRead != 0x31 || n.maxWrite != 0x41 || n.ctxOff != 0x80 || n.secBuffer != nil {
		t.Fatalf("%+v", n)
	}
	// a security buffer must lie after the fixed part
	binary.LittleEndian.PutUint16(m[headerLen+56:], headerLen+63)
	binary.LittleEndian.PutUint16(m[headerLen+58:], 1)
	if _, err := parseNegotiateResp(m); !errors.Is(err, errBadField) {
		t.Fatalf("a buffer inside the fixed part: %v", err)
	}
}

// ctxMsg builds a message holding the given raw contexts at offset off.
func ctxMsg(off int, ctxs ...[]byte) []byte {
	m := make([]byte, off)
	for _, c := range ctxs {
		m = append(m, c...)
		for len(m)%8 != 0 {
			m = append(m, 0)
		}
	}
	return m
}

func ctxRaw(typ uint16, d []byte) []byte {
	b := make([]byte, 8, 8+len(d))
	binary.LittleEndian.PutUint16(b, typ)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(d)))
	return append(b, d...)
}

func u16le(v ...uint16) []byte {
	var b []byte
	for _, x := range v {
		b = binary.LittleEndian.AppendUint16(b, x)
	}
	return b
}

func TestClientServerContextBounds(t *testing.T) {
	defer recovered(t)
	const off = headerLen + 64
	pre := ctxRaw(ctxPreauthIntegrity, u16le(1, 0, hashIDSHA512))
	preSalt := ctxRaw(ctxPreauthIntegrity, append(u16le(1, 2, hashIDSHA512), 9, 9))
	enc := ctxRaw(ctxEncryption, u16le(1, cipherAES128GCM))
	sig := ctxRaw(ctxSigning, u16le(1, signIDAESCMAC))

	ok := func(name string, m []byte, off, count int) clServerContexts {
		t.Helper()
		c, err := parseServerContexts(m, off, count)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return c
	}
	c := ok("all three", ctxMsg(off, pre, enc, sig), off, 3)
	if c.hash != hashIDSHA512 || !c.hasCipher || c.cipher != cipherAES128GCM || !c.hasSign || c.signing != signIDAESCMAC {
		t.Fatalf("%+v", c)
	}
	if c := ok("preauth only", ctxMsg(off, pre), off, 1); c.hasCipher || c.hasSign {
		t.Fatalf("%+v", c)
	}
	ok("salt", ctxMsg(off, preSalt), off, 1)
	ok("encryption twice is the server's problem only at two", ctxMsg(off, pre, enc), off, 2)

	bad := func(name string, m []byte, off, count int) {
		t.Helper()
		if _, err := parseServerContexts(m, off, count); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad("count 0", ctxMsg(off, pre), off, 0)
	bad("count negative", ctxMsg(off, pre), off, -1)
	bad("count over the cap", ctxMsg(off, pre), off, maxNegotiateContexts+1)
	ok("count at the cap is only rejected by the contexts it lacks", ctxMsg(off, pre), off, 1)
	bad("offset inside the fixed part", ctxMsg(off-8, pre), off-8, 1)
	bad("unaligned offset", ctxMsg(off+4, pre), off+4, 1)
	bad("offset past the end", ctxMsg(off, pre), len(ctxMsg(off, pre))+8, 1)
	bad("two preauth", ctxMsg(off, pre, pre), off, 2)
	bad("no preauth", ctxMsg(off, enc), off, 1)
	bad("two encryption", ctxMsg(off, pre, enc, enc), off, 3)
	bad("two signing", ctxMsg(off, pre, sig, sig), off, 3)
	bad("count beyond the list", ctxMsg(off, pre), off, 2)

	// header truncated: fewer than 8 bytes remain
	full := ctxMsg(off, pre)
	bad("header cut", full[:len(full)-len(pre)+7], off, 1)
	// an unknown type alone has no preauth: rejected, but only after it was read whole
	if _, err := parseServerContexts(append(ctxMsg(off), ctxRaw(99, nil)...), off, 1); err == nil {
		t.Error("an unknown context alone")
	}
	// data length runs one byte past the end
	cut := ctxMsg(off, pre)
	cut = cut[:off+8+5] // data was 6 bytes
	bad("data cut by one", cut, off, 1)
	// the preauth data checks
	bad("preauth data 5 bytes", ctxMsg(off, ctxRaw(ctxPreauthIntegrity, []byte{1, 0, 0, 0, 1})), off, 1)
	bad("preauth hash count 2", ctxMsg(off, ctxRaw(ctxPreauthIntegrity, u16le(2, 0, hashIDSHA512))), off, 1)
	bad("salt longer than the data", ctxMsg(off, ctxRaw(ctxPreauthIntegrity, u16le(1, 3, hashIDSHA512))), off, 1)
	ok("salt exactly the data", ctxMsg(off, ctxRaw(ctxPreauthIntegrity, append(u16le(1, 1, hashIDSHA512), 7))), off, 1)
	// the encryption and signing checks
	bad("encryption 3 bytes", ctxMsg(off, pre, ctxRaw(ctxEncryption, []byte{1, 0, 1})), off, 2)
	bad("encryption two ciphers", ctxMsg(off, pre, ctxRaw(ctxEncryption, u16le(2, 1, 2))), off, 2)
	bad("signing 3 bytes", ctxMsg(off, pre, ctxRaw(ctxSigning, []byte{1, 0, 1})), off, 2)
	bad("signing two algorithms", ctxMsg(off, pre, ctxRaw(ctxSigning, u16le(2, 1, 2))), off, 2)
	// an unknown type between known ones is skipped, and the walk keeps its place
	if c := ok("unknown skipped", ctxMsg(off, ctxRaw(99, []byte{1, 2, 3}), pre, enc), off, 3); !c.hasCipher {
		t.Fatalf("%+v", c)
	}
}

func TestClientFullSizeBounds(t *testing.T) {
	defer recovered(t)
	b := make([]byte, 32)
	binary.LittleEndian.PutUint64(b[0:], 100)
	binary.LittleEndian.PutUint64(b[8:], 40)
	binary.LittleEndian.PutUint64(b[16:], 50)
	binary.LittleEndian.PutUint32(b[24:], 8)
	binary.LittleEndian.PutUint32(b[28:], 512)
	f, err := parseFullSize(b)
	if err != nil {
		t.Fatal(err)
	}
	if f != (clFullSize{unit: 4096, total: 100, free: 50, avail: 40}) {
		t.Fatalf("%+v", f)
	}
	if _, err := parseFullSize(b[:31]); !errors.Is(err, errShort) {
		t.Fatalf("31 bytes: %v", err)
	}
}

func TestClientFileTime(t *testing.T) {
	const delta = 11644473600
	if !fileTime(0).IsZero() {
		t.Fatal("zero")
	}
	if !fileTime(delta*10_000_000 - 1).IsZero() {
		t.Fatal("just before the epoch")
	}
	if got := fileTime(delta * 10_000_000); !got.Equal(time.Unix(0, 0)) {
		t.Fatalf("the epoch: %v", got)
	}
	if got := fileTime(delta*10_000_000 + 10_000_000 + 7); !got.Equal(time.Unix(1, 700)) {
		t.Fatalf("one second and 700 ns: %v", got)
	}
}

// dirEntry builds a FileDirectoryInformation record for name, with the given
// NextEntryOffset.
func clDirRec(name string, next uint32, size uint64, attrs uint32) []byte {
	n := utf16leBytes(name)
	e := make([]byte, 64, 64+len(n))
	binary.LittleEndian.PutUint32(e, next)
	binary.LittleEndian.PutUint64(e[40:], size)
	binary.LittleEndian.PutUint32(e[56:], attrs)
	binary.LittleEndian.PutUint32(e[60:], uint32(len(n)))
	return append(e, n...)
}

func TestClientDirEntryBounds(t *testing.T) {
	defer recovered(t)
	a := clDirRec("ab", 0, 5, 0x20)
	got, err := parseDirEntries(a)
	if err != nil || len(got) != 1 || got[0].Name != "ab" || got[0].Size != 5 || got[0].Attrs != 0x20 {
		t.Fatalf("%+v %v", got, err)
	}
	// the name ends exactly at the end
	if _, err := parseDirEntries(a[:len(a)-1]); err == nil {
		t.Error("a name one byte short")
	}
	// fewer than 64 bytes
	if _, err := parseDirEntries(a[:63]); err == nil {
		t.Error("63 bytes")
	}
	if _, err := parseDirEntries(nil); err == nil {
		t.Error("empty")
	}
	// an odd name length
	odd := clDirRec("ab", 0, 0, 0)
	binary.LittleEndian.PutUint32(odd[60:], 3)
	if _, err := parseDirEntries(odd); err == nil {
		t.Error("odd name length")
	}
	// a name length larger than the buffer
	huge := clDirRec("ab", 0, 0, 0)
	binary.LittleEndian.PutUint32(huge[60:], 1<<31)
	if _, err := parseDirEntries(huge); err == nil {
		t.Error("a 2 GiB name")
	}
	// two entries: next exactly at the end of the first name, the second last
	first := clDirRec("ab", 0, 1, 0)
	binary.LittleEndian.PutUint32(first, uint32(len(first)))
	two := append(append([]byte(nil), first...), clDirRec("c", 0, 2, 0)...)
	got, err = parseDirEntries(two)
	if err != nil || len(got) != 2 || got[0].Name != "ab" || got[1].Name != "c" || got[1].Size != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	// next one byte inside the name
	in := append([]byte(nil), two...)
	binary.LittleEndian.PutUint32(in, uint32(len(first)-1))
	if _, err := parseDirEntries(in); err == nil {
		t.Error("next inside the name")
	}
	// the next record starting inside the name of this one, laid out so that
	// every field it then reads is valid: only the overlap is wrong
	overlap := make([]byte, 128)
	binary.LittleEndian.PutUint32(overlap, 64)
	binary.LittleEndian.PutUint32(overlap[60:], 4)
	if got, err := parseDirEntries(overlap); err == nil {
		t.Errorf("overlapping records accepted: %+v", got)
	}
	// next of zero for the last only; next pointing past the buffer
	past := append([]byte(nil), two...)
	binary.LittleEndian.PutUint32(past, uint32(len(two)+1))
	if _, err := parseDirEntries(past); err == nil {
		t.Error("next past the buffer")
	}
	// next at exactly the end of the buffer leaves nothing to decode
	end := append([]byte(nil), first...)
	binary.LittleEndian.PutUint32(end, uint32(len(end)))
	if _, err := parseDirEntries(end); err == nil {
		t.Error("next at the end, with no entry behind it")
	}
	// a size above MaxInt64 reads as zero
	big := clDirRec("x", 0, 1<<63, 0)
	if got, err := parseDirEntries(big); err != nil || got[0].Size != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	if got, err := parseDirEntries(clDirRec("x", 0, 1<<63-1, 0)); err != nil || got[0].Size != 1<<63-1 {
		t.Fatalf("%+v %v", got, err)
	}
}

func ntlmChal(flags uint32, tiOff, tiLen int, total int) []byte {
	b := make([]byte, max(total, 48))
	copy(b, ntlmSignature[:])
	binary.LittleEndian.PutUint32(b[8:], ntlmChallenge)
	binary.LittleEndian.PutUint32(b[20:], flags)
	copy(b[24:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	binary.LittleEndian.PutUint16(b[40:], uint16(tiLen))
	binary.LittleEndian.PutUint32(b[44:], uint32(tiOff))
	return b[:total]
}

func TestClientChallengeBounds(t *testing.T) {
	defer recovered(t)
	c, err := parseChallenge(ntlmChal(ntlmNegotiateUnicode|ntlmNegotiateKeyExchange, 48, 4, 52))
	if err != nil || c.flags != ntlmNegotiateUnicode|ntlmNegotiateKeyExchange || c.nonce != [8]byte{1, 2, 3, 4, 5, 6, 7, 8} || len(c.targetInfo) != 4 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := parseChallenge(ntlmChal(ntlmNegotiateUnicode, 0, 0, 48)); err != nil {
		t.Fatalf("no target info: %v", err)
	}
	for name, b := range map[string][]byte{
		"47 bytes":            ntlmChal(ntlmNegotiateUnicode, 0, 0, 47),
		"not unicode":         ntlmChal(0, 48, 4, 52),
		"info one byte short": ntlmChal(ntlmNegotiateUnicode, 48, 5, 52),
		"info before 48":      ntlmChal(ntlmNegotiateUnicode, 47, 4, 52),
		"info at the end":     ntlmChal(ntlmNegotiateUnicode, 52, 1, 52),
		"info far away":       ntlmChal(ntlmNegotiateUnicode, 60000, 4, 52),
	} {
		if _, err := parseChallenge(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	wrongSig := ntlmChal(ntlmNegotiateUnicode, 0, 0, 48)
	wrongSig[0] ^= 1
	if _, err := parseChallenge(wrongSig); !errors.Is(err, errNotNTLM) {
		t.Errorf("signature: %v", err)
	}
	wrongType := ntlmChal(ntlmNegotiateUnicode, 0, 0, 48)
	wrongType[8] = 1
	if _, err := parseChallenge(wrongType); !errors.Is(err, errNotNTLM) {
		t.Errorf("type: %v", err)
	}
	if _, err := parseChallenge(ntlmChal(ntlmNegotiateUnicode, 48, 4, 52)[:51]); err == nil {
		t.Error("info runs one byte past the end")
	}
}

func TestClientAVPairBounds(t *testing.T) {
	defer recovered(t)
	pair := func(id uint16, v ...byte) []byte {
		return append(u16le(id, uint16(len(v))), v...)
	}
	eol := pair(avEOL)
	ids, vals, err := avPairs(append(append(pair(7, 1, 2), pair(9)...), eol...))
	if err != nil || len(ids) != 2 || ids[0] != 7 || ids[1] != 9 || len(vals[0]) != 2 || vals[0][1] != 2 || len(vals[1]) != 0 {
		t.Fatalf("%v %v %v", ids, vals, err)
	}
	if _, _, err := avPairs(eol); err != nil {
		t.Fatalf("only the EOL: %v", err)
	}
	for name, b := range map[string][]byte{
		"empty":             nil,
		"3 bytes":           {7, 0, 0},
		"no EOL":            pair(7, 1),
		"value too long":    append(u16le(7, 3), 1, 2),
		"EOL claims a body": append(u16le(avEOL, 5), 1),
	} {
		if _, _, err := avPairs(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the value ends exactly at the end of the buffer, then the EOL must follow
	if _, _, err := avPairs(append(u16le(7, 2), 1, 2)); err == nil {
		t.Error("a pair that fills the buffer leaves no EOL")
	}
}
