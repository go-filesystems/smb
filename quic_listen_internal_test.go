//go:build !noquic

package smb

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
)

// quic-go's Listen cannot fail on a valid configuration, so the failure is
// injected: the error comes back, and the UDP port is released.
func TestListenQUICListenFailureReleasesThePort(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	probe.Close()
	boom := errors.New("injected")
	old := quicListen
	quicListen = func(*quic.Transport, *tls.Config, *quic.Config) (*quic.Listener, error) { return nil, boom }
	defer func() { quicListen = old }()
	if l, err := ListenQUIC(addr, &tls.Config{}); !errors.Is(err, boom) || l != nil {
		t.Fatalf("ListenQUIC = %v, %v; want the injected error", l, err)
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("the port was not released: %v", err)
	}
	pc.Close()
}
