// SPDX-License-Identifier: BSD-3-Clause

//go:build noquic

package smb

import (
	"crypto/tls"
	"errors"
	"net"
)

// ErrNoQUIC is what [ListenQUIC] returns in a build made with -tags noquic,
// which carries no QUIC stack.
var ErrNoQUIC = errors.New("smb: built with the noquic tag")

// A QUICOption adjusts [ListenQUIC]; there are none in a noquic build.
type QUICOption func()

// ListenQUIC is unavailable in a noquic build.
func ListenQUIC(string, *tls.Config, ...QUICOption) (net.Listener, error) {
	return nil, ErrNoQUIC
}
