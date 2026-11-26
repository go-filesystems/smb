package smb

import (
	"errors"
	"testing"
)

func TestClientResponseDecodersRefuseShortBodies(t *testing.T) {
	defer recovered(t)
	if _, err := parseReadResp(clMsg(17, 15), 10); !errors.Is(err, errShort) {
		t.Errorf("READ: %v", err)
	}
	if _, err := parseWriteResp(clMsg(17, 15)); !errors.Is(err, errShort) {
		t.Errorf("WRITE: %v", err)
	}
	if _, err := parseCreateResp(clMsg(89, 87)); !errors.Is(err, errShort) {
		t.Errorf("CREATE: %v", err)
	}
	if _, err := parseInfoResp(clMsg(9, 7)); !errors.Is(err, errShort) {
		t.Errorf("QUERY_INFO: %v", err)
	}
	if _, _, err := parseSessionSetupResp(clMsg(9, 7)); !errors.Is(err, errShort) {
		t.Errorf("SESSION_SETUP: %v", err)
	}
	if _, err := parseNegotiateResp(clMsg(65, 63)); !errors.Is(err, errShort) {
		t.Errorf("NEGOTIATE: %v", err)
	}
	if _, err := parseTreeConnectResp(clMsg(16, 15)); !errors.Is(err, errShort) {
		t.Errorf("TREE_CONNECT: %v", err)
	}
	// the right size with the wrong structure size is not the same error
	if _, err := parseWriteResp(clMsg(9, 16)); err == nil || errors.Is(err, errShort) {
		t.Errorf("WRITE with a wrong structure size: %v", err)
	}
	if n, err := parseWriteResp(func() []byte { m := clMsg(17, 16); m[headerLen+4] = 7; return m }()); err != nil || n != 7 {
		t.Errorf("WRITE count: %d %v", n, err)
	}
	if d, err := parseReadResp(func() []byte {
		m := clMsg(17, 16+3)
		m[headerLen+2] = headerLen + 16
		m[headerLen+4] = 3
		copy(m[headerLen+16:], "abc")
		return m
	}(), 3); err != nil || string(d) != "abc" {
		t.Errorf("READ data: %q %v", d, err)
	}
}

func TestMustAEADRefusesAKeyThatDoesNotFit(t *testing.T) {
	if a := mustAEAD(cipherAES128GCM, make([]byte, 16)); a == nil {
		t.Fatal("no cipher for a good key")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a 5-byte key made a cipher")
		}
	}()
	mustAEAD(cipherAES128GCM, make([]byte, 5))
}

func TestClientPathOfTheRootIsEmpty(t *testing.T) {
	for _, p := range []string{"", ".", "/", "./", "//"} {
		if got, err := clPath(p); err != nil || got != "" {
			t.Errorf("%q: %q %v", p, got, err)
		}
	}
	if got, err := clPath("a//b/./c/"); err != nil || got != `a\b\c` {
		t.Errorf("%q %v", got, err)
	}
}

// A frame that breaks the rules ends the connection: the request waiting for
// its answer fails, and so does every later one.
func TestClientConnectionEndsOnAProtocolViolation(t *testing.T) {
	_, s := newFake(t, func(r fkReq) (uint32, []byte) {
		if r.cmd == cmdQueryInfo {
			return fkBadCommand, nil
		}
		return stOK, fkCreate(0x10, 0, 1)
	})
	if _, err := s.Stat(ctx0, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Statfs(ctx0); err == nil || !transportErr(err) {
		t.Fatalf("a response to the wrong command: %v", err)
	}
	if _, err := s.Stat(ctx0, "a"); err == nil {
		t.Fatal("the connection survived")
	}
}
