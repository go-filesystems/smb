//go:build !plan9

package smb

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// The errors a server out of descriptors, or one whose client left before it was
// accepted, really gets from accept(2), as the standard library wraps them.
func TestAcceptRetriesTheRealErrnos(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED} {
		s := limitedServer(0, -1)
		err := &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", errno)}
		ln := newScripted(3, err)
		done := make(chan error, 1)
		go func() { done <- s.Serve(ln) }()
		select {
		case <-ln.again:
		case e := <-done:
			t.Fatalf("%v: Serve returned %v", errno, e)
		case <-time.After(10 * time.Second):
			t.Fatalf("%v: never accepted after the failures", errno)
		}
		s.Close()
		<-done
	}
}
