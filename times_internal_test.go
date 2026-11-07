package smb

import (
	"encoding/binary"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

func TestWriteTimesLayout(t *testing.T) {
	m := time.Date(2019, 3, 4, 5, 6, 8, 0, time.UTC)
	ft := filesystem.FileTimes{
		Btime: filesystem.NewTimestamp(m.Add(-time.Hour), time.Millisecond),
		Atime: filesystem.NewTimestamp(m.Add(time.Hour), time.Second),
		Mtime: filesystem.NewTimestamp(m, 2*time.Second),
		// Ctime not recorded.
	}
	b := make([]byte, 32)
	writeTimes(b, &ft)
	le := binary.LittleEndian
	for i, want := range []uint64{filetime(m.Add(-time.Hour)), filetime(m.Add(time.Hour)), filetime(m), 0} {
		if got := le.Uint64(b[i*8:]); got != want {
			t.Errorf("field %d = %d, want %d", i, got, want)
		}
	}
	// 2019-03-04 05:06:08 UTC = 17959 days and 05:06:08 after 1970 =
	// 1551675968 s; plus 11644473600 s from 1601 to 1970, in 100 ns ticks.
	if got := filetime(m); got != 131961495680000000 {
		t.Errorf("filetime = %d", got)
	}
}

func TestFiletimeOfBeforeTheEpochIsZero(t *testing.T) {
	old := filesystem.NewTimestamp(time.Date(1500, 1, 1, 0, 0, 0, 0, time.UTC), time.Second)
	if filetimeOf(old) != 0 {
		t.Error("a time before 1601 has no FILETIME")
	}
	if filetimeOf(filesystem.Timestamp{}) != 0 {
		t.Error("not recorded must be 0")
	}
}

func TestWriteTimesNilIsNow(t *testing.T) {
	b := make([]byte, 32)
	writeTimes(b, nil)
	now := filetime(time.Now())
	for i := 0; i < 4; i++ {
		got := binary.LittleEndian.Uint64(b[i*8:])
		if got > now || now-got > 60*10_000_000 {
			t.Errorf("field %d = %d, now %d", i, got, now)
		}
	}
}
