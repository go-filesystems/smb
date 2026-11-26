//go:build unix

package client

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// checkOwner refuses a file that the current user does not own.
func checkOwner(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the owner")
	}
	if uid := os.Geteuid(); int(st.Uid) != uid {
		return fmt.Errorf("owned by uid %d, not by the current user (uid %d)", st.Uid, uid)
	}
	return nil
}
