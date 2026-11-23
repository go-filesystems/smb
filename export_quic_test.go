//go:build !noquic

package smb

import "time"

// SetQUICHandshakeTimeout lets the external tests lengthen the handshake bound
// under CPU emulation, where one ECDSA handshake can outlast the production 5 s.
func SetQUICHandshakeTimeout(d time.Duration) (restore func()) {
	old := quicHandshakeTimeout
	quicHandshakeTimeout = d
	return func() { quicHandshakeTimeout = old }
}
