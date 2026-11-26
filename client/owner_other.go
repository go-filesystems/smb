//go:build !unix

package client

import (
	"errors"
	"os"
)

// checkOwner cannot be answered here, so the file is refused: a credentials
// file whose ownership is unknown is not trusted.
func checkOwner(os.FileInfo) error {
	return errors.New("ownership check is not supported on this platform")
}
