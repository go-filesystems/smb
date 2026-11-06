package smb_test

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

// Many readers of one file, from several goroutines of one connection, through
// a client this project did not write: the server answers them beside each
// other (up to MaxInFlight) and every reply reaches the request it answers.
// Run under the race detector, which is the judge of the shared state.
func TestParallelReadsOfOneFileThroughOneConnection(t *testing.T) {
	for _, width := range []int{-1, 3, 0} {
		t.Run(fmt.Sprintf("MaxInFlight %d", width), func(t *testing.T) {
			mem := newMemFS(true)
			addr, srv := serve(t)
			srv.MaxInFlight = width
			srv.MaxInFlightTotal = 8
			if err := srv.Share("disk", mem); err != nil {
				t.Fatal(err)
			}
			want := make([]byte, 3<<20)
			for i := range want {
				want[i] = byte(i*7 + i>>8)
			}
			if err := mem.WriteFile("/big.bin", want, 0o644); err != nil {
				t.Fatal(err)
			}
			s, done := dial(t, addr, "alice", "hunter2")
			defer done()
			fs, err := s.Mount("disk")
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Umount()
			f, err := fs.Open("big.bin")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			const workers, block = 12, 96 << 10
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					buf := make([]byte, block)
					for i := w; i*block < len(want); i += workers {
						n, err := f.ReadAt(buf, int64(i*block))
						if err != nil && n == 0 {
							t.Errorf("ReadAt(%d): %v", i*block, err)
							return
						}
						if !bytes.Equal(buf[:n], want[i*block:i*block+n]) {
							t.Errorf("ReadAt(%d) returned the wrong bytes", i*block)
							return
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}
