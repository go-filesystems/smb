package smb

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func frameOf(typ byte, n int, body []byte) []byte {
	return append([]byte{typ, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

func TestReadFrameMaxBounds(t *testing.T) {
	if _, err := readFrameMax(bytes.NewReader(nil), 100); err != io.EOF {
		t.Fatalf("nothing to read: %v", err)
	}
	if _, err := readFrameMax(bytes.NewReader([]byte{0, 0}), 100); err != io.ErrUnexpectedEOF {
		t.Fatalf("half a header: %v", err)
	}
	if _, err := readFrameMax(bytes.NewReader(frameOf(1, 3, []byte("abc"))), 100); err == nil || !strings.Contains(err.Error(), "not a session message") {
		t.Fatalf("a keep-alive or request type: %v", err)
	}
	if _, err := readFrameMax(bytes.NewReader(frameOf(0, 0, nil)), 100); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty: %v", err)
	}
	if b, err := readFrameMax(bytes.NewReader(frameOf(0, 100, bytes.Repeat([]byte("x"), 100))), 100); err != nil || len(b) != 100 {
		t.Fatalf("exactly the limit: %d %v", len(b), err)
	}
	if _, err := readFrameMax(bytes.NewReader(frameOf(0, 101, bytes.Repeat([]byte("x"), 101))), 100); err == nil || !strings.Contains(err.Error(), "larger than the 100-byte limit") {
		t.Fatalf("one over the limit: %v", err)
	}
	// a body shorter than the header says
	if _, err := readFrameMax(bytes.NewReader(frameOf(0, 10, []byte("12345"))), 100); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a short body: %v", err)
	}
	// a large body, delivered in small pieces, past the first allocation
	big := bytes.Repeat([]byte("0123456789abcdef"), 40000) // 640 KB
	got, err := readFrameMax(iotest.HalfReader(bytes.NewReader(frameOf(0, len(big), big))), 1<<20)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("a 640 KB body: %d %v", len(got), err)
	}
	// ... and cut inside the growth
	cut := frameOf(0, len(big), big)[:4+frameFirstRead+1000]
	if _, err := readFrameMax(bytes.NewReader(cut), 1<<20); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a cut large body: %v", err)
	}
	// the announced length costs nothing until the bytes arrive
	if _, err := readFrameMax(bytes.NewReader(frameOf(0, 1<<23, []byte("x"))), 1<<24); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("an 8 MiB announcement with one byte behind it: %v", err)
	}
}

func TestWriteFrameBounds(t *testing.T) {
	var w bytes.Buffer
	if err := writeFrame(&w, []byte("abc")); err != nil || !bytes.Equal(w.Bytes(), []byte{0, 0, 0, 3, 'a', 'b', 'c'}) {
		t.Fatalf("%v %v", w.Bytes(), err)
	}
	if err := writeFrame(io.Discard, make([]byte, maxFrameLen-1)); err != nil {
		t.Fatalf("the largest body a three-byte length can say: %v", err)
	}
	if err := writeFrame(io.Discard, make([]byte, maxFrameLen)); err == nil {
		t.Fatal("a body one over the three-byte length")
	}
}
