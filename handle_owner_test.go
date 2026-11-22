package smb

import (
	"encoding/binary"
	"testing"
)

// An Open belongs to the session and the tree that created it ([MS-SMB2] 3.3.5.9
// Open.Session, Open.TreeConnect). READ (3.3.5.10), WRITE (3.3.5.12) and CLOSE
// (3.3.5.13), and every other command that names a FileId, fail with
// STATUS_FILE_CLOSED for a request of any other session or tree. These tests pin
// that for each handler, and for the all-ones FileId of 3.3.5.2.7.2.

// ownerConn is alice's connection: session 1, tree 5 on a share, and one open
// of hers on it. Session 2 (bob) has a tree 6 on the SAME share, and alice has a
// second tree 7 of her own, so a request can differ from the Open in its session,
// in its tree, or in both, while its own tree is valid and the lookup of the
// handle is what refuses it.
func ownerConn(t *testing.T) (*conn, *openFile, *tinyFS) {
	t.Helper()
	c := sessionConn(t)
	fs := &tinyFS{body: []byte("alice's secret")}
	sh := &share{name: "private", fsys: fs}
	c.trees[5] = &treeConn{sh: sh, session: 1}
	c.trees[6] = &treeConn{sh: sh, session: 2}
	c.trees[7] = &treeConn{sh: sh, session: 1}
	of := &openFile{path: "/file.txt", share: sh, session: 1, tree: 5}
	binary.LittleEndian.PutUint64(of.id[:8], 1)
	binary.LittleEndian.PutUint64(of.id[8:], 5)
	c.files[of.id] = of
	return c, of, fs
}

// TestAuditOpusHandleCrossesSessions: session 2, holding no tree on the share,
// reads, writes and closes a handle that session 1 opened.
func TestAuditOpusHandleCrossesSessions(t *testing.T) {
	c, of, fs := ownerConn(t)

	rd := make([]byte, 48)
	binary.LittleEndian.PutUint32(rd[4:], 64) // length
	copy(rd[16:], of.id[:])
	out, err := c.dispatchChain(requestIn(cmdRead, 2, 0, rd)) // bob, tree 0
	if err != nil {
		t.Fatal(err)
	}
	if st := statusOf(t, out); st == statusSuccess {
		n := binary.LittleEndian.Uint32(out[headerLen+4:])
		t.Errorf("bob read alice's handle: %q", out[headerLen+16:headerLen+16+int(n)])
	}

	payload := []byte("bob was here")
	wr := make([]byte, 48)
	binary.LittleEndian.PutUint16(wr[2:], headerLen+48)
	binary.LittleEndian.PutUint32(wr[4:], uint32(len(payload)))
	copy(wr[16:], of.id[:])
	out, err = c.dispatchChain(requestIn(cmdWrite, 2, 0, append(wr, payload...)))
	if err != nil {
		t.Fatal(err)
	}
	if st := statusOf(t, out); st == statusSuccess {
		t.Errorf("bob wrote through alice's handle; file is now %q", fs.body)
	}

	cl := make([]byte, 24)
	copy(cl[8:], of.id[:])
	out, _ = c.dispatchChain(requestIn(cmdClose, 2, 0, cl))
	if st := statusOf(t, out); st == statusSuccess {
		t.Errorf("bob closed alice's handle (still held: %v)", c.files[of.id] != nil)
	}
}

// ownerBody is a request body of the command with fid at the offset the command
// carries its FileId at.
func ownerBody(cmd command, fid [16]byte) []byte {
	return ownerBodyCode(cmd, 0, fid)
}

// ownerBodyCode is ownerBody with the CtlCode of an IOCTL.
func ownerBodyCode(cmd command, code uint32, fid [16]byte) []byte {
	b := make([]byte, 128)
	if cmd == cmdIoctl {
		binary.LittleEndian.PutUint32(b[4:], code)
	}
	off := map[command]int{
		cmdClose: 8, cmdFlush: 8, cmdRead: 16, cmdWrite: 16, cmdLock: 8,
		cmdIoctl: 8, cmdQueryDirectory: 8, cmdChangeNotify: 8, cmdQueryInfo: 24, cmdSetInfo: 16,
	}[cmd]
	copy(b[off:], fid[:])
	if cmd == cmdRead || cmd == cmdQueryDirectory || cmd == cmdQueryInfo {
		binary.LittleEndian.PutUint32(b[4:], 64)
	}
	return b
}

var ownerCommands = []command{
	cmdClose, cmdFlush, cmdRead, cmdWrite, cmdLock,
	cmdQueryDirectory, cmdChangeNotify, cmdQueryInfo, cmdSetInfo,
}

// The three IOCTLs that take a handle: the pipe transceive, the resume key and
// the server-side copy. Each looks the FileId up itself.
func TestEveryIoctlRefusesAnotherSessionsHandle(t *testing.T) {
	for _, code := range []uint32{fsctlPipeTransceive, fsctlSrvRequestResumeKey, fsctlSrvCopyChunk, fsctlSrvCopyChunkWrite} {
		for _, fid := range []struct {
			name    string
			id      [16]byte
			related bool
		}{{"its id", [16]byte{}, false}, {"all-ones", allOnesFileID, true}} {
			c, of, _ := ownerConn(t)
			id := fid.id
			if fid.name == "its id" {
				id = of.id
			}
			m := requestIn(cmdIoctl, 2, 6, ownerBodyCode(cmdIoctl, code, id))
			if fid.related {
				binary.LittleEndian.PutUint32(m[offFlags:], flagRelatedOps)
			}
			out, err := c.dispatchChain(m)
			if err != nil {
				t.Fatal(err)
			}
			if st := statusOf(t, out); st != statusFileClosed {
				t.Errorf("IOCTL %#x with %s from another session answered %#x, want STATUS_FILE_CLOSED", code, fid.name, st)
			}
		}
	}
}

// One test per handler: a request of another session, or of another tree of the
// same session, is STATUS_FILE_CLOSED and leaves the Open as it was.
func TestEveryHandlerRefusesAnotherSessionsOrTreesHandle(t *testing.T) {
	for _, cmd := range ownerCommands {
		for _, who := range []struct {
			name    string
			session uint64
			tree    uint32
		}{
			{"another session", 2, 6},
			{"another tree of the same session", 1, 7},
		} {
			t.Run(cmd.String()+"/"+who.name, func(t *testing.T) {
				c, of, fs := ownerConn(t)
				before := string(fs.body)
				out, err := c.dispatchChain(requestIn(cmd, who.session, who.tree, ownerBody(cmd, of.id)))
				if err != nil {
					t.Fatal(err)
				}
				if st := statusOf(t, out); st != statusFileClosed {
					t.Errorf("%v from %s answered %#x, want STATUS_FILE_CLOSED", cmd, who.name, st)
				}
				if c.files[of.id] == nil {
					t.Errorf("%v from %s closed the owner's handle", cmd, who.name)
				}
				if string(fs.body) != before {
					t.Errorf("%v from %s changed the file to %q", cmd, who.name, fs.body)
				}
			})
		}
	}
}

// The owner itself still reaches its handle: the check is on who asks, and a
// refusal of everyone would pass the tests above.
func TestTheOwnerStillReachesItsHandle(t *testing.T) {
	c, of, _ := ownerConn(t)
	out, err := c.dispatchChain(requestIn(cmdRead, 1, 5, ownerBody(cmdRead, of.id)))
	if err != nil {
		t.Fatal(err)
	}
	if st := statusOf(t, out); st != statusSuccess {
		t.Errorf("the owner's READ answered %#x", st)
	}
}

// [MS-SMB2] 3.3.5.2.7.2: the all-ones FileId means "what the previous operation
// of this compound opened". It never means a connection's last open: not in a
// request that is not related to one, and not in a related request that starts a
// chain of its own.
func TestAllOnesFileIDIsNotAConnectionWideLastFile(t *testing.T) {
	for _, cmd := range ownerCommands {
		t.Run(cmd.String()+"/unrelated", func(t *testing.T) {
			c, of, _ := ownerConn(t)
			// alice's CREATE was the last thing this connection did
			out, err := c.dispatchChain(requestIn(cmd, 2, 6, ownerBody(cmd, allOnesFileID)))
			if err != nil {
				t.Fatal(err)
			}
			if st := statusOf(t, out); st != statusFileClosed {
				t.Errorf("%v with an all-ones id answered %#x, want STATUS_FILE_CLOSED", cmd, st)
			}
			if c.files[of.id] == nil {
				t.Errorf("%v with an all-ones id reached alice's handle", cmd)
			}
		})
		t.Run(cmd.String()+"/related first operation", func(t *testing.T) {
			c, of, _ := ownerConn(t)
			m := requestIn(cmd, 2, 6, ownerBody(cmd, allOnesFileID))
			binary.LittleEndian.PutUint32(m[offFlags:], flagRelatedOps)
			out, err := c.dispatchChain(m)
			if err != nil {
				t.Fatal(err)
			}
			if st := statusOf(t, out); st != statusFileClosed {
				t.Errorf("%v with a related all-ones id answered %#x, want STATUS_FILE_CLOSED", cmd, st)
			}
			if c.files[of.id] == nil {
				t.Errorf("%v with a related all-ones id reached alice's handle", cmd)
			}
		})
	}
}

// A FileId shorter than 16 bytes names nothing, and must not be read past its end.
func TestAShortFileIDNamesNothing(t *testing.T) {
	c, _, _ := ownerConn(t)
	if got := c.fileByID(header{sessionID: 1, treeID: 5}, make([]byte, 15)); got != nil {
		t.Error("a 15-byte FileId resolved")
	}
	if got := c.fileByID(header{sessionID: 1, treeID: 5}, nil); got != nil {
		t.Error("an empty FileId resolved")
	}
}

// Across sessions inside one chain: a related operation inherits the session and
// tree of the first, so the all-ones id of a chain that bob starts is bob's open,
// and is held to the same check if it names someone else's.
func TestRelatedFileIDResolvesOnlyWithinItsOwnChain(t *testing.T) {
	c, _, _ := ownerConn(t)

	// alice's chain: CREATE, then a related READ that names the file by all-ones.
	name := utf16le("file.txt")
	create := make([]byte, 56)
	binary.LittleEndian.PutUint32(create[36:], dispOpen)
	binary.LittleEndian.PutUint16(create[44:], uint16(headerLen+56))
	binary.LittleEndian.PutUint16(create[46:], uint16(len(name)))
	first := requestIn(cmdCreate, 1, 5, append(create, name...))
	for len(first)%8 != 0 {
		first = append(first, 0)
	}
	binary.LittleEndian.PutUint32(first[offNextCommand:], uint32(len(first)))
	second := requestIn(cmdRead, 1, 5, ownerBody(cmdRead, allOnesFileID))
	binary.LittleEndian.PutUint32(second[offFlags:], flagRelatedOps)
	out, err := c.dispatchChain(append(first, second...))
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseHeader(out)
	if err != nil || h.status != statusSuccess || h.nextCommand == 0 {
		t.Fatalf("alice's CREATE: %v %#x", err, h.status)
	}
	if st := statusOf(t, out[h.nextCommand:]); st != statusSuccess {
		t.Errorf("alice's related READ of her own CREATE answered %#x", st)
	}

	// bob's chain starts with a related READ: there is nothing before it in HIS
	// chain, and alice's open is not "the previous operation".
	m := requestIn(cmdRead, 2, 6, ownerBody(cmdRead, allOnesFileID))
	binary.LittleEndian.PutUint32(m[offFlags:], flagRelatedOps)
	out, err = c.dispatchChain(m)
	if err != nil {
		t.Fatal(err)
	}
	if st := statusOf(t, out); st != statusFileClosed {
		t.Errorf("bob's related all-ones READ answered %#x, want STATUS_FILE_CLOSED", st)
	}

	// An all-ones id that no chain substituted names nothing, whoever asks.
	for _, hd := range []header{
		{flags: flagRelatedOps, sessionID: 1, treeID: 5},
		{sessionID: 1, treeID: 5},
	} {
		if got := c.fileByID(hd, allOnesFileID[:]); got != nil {
			t.Errorf("an unsubstituted all-ones id resolved for %+v", hd)
		}
	}
}
