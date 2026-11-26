package client

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Target is a parsed //host[:port]/share[/path] name.
type Target struct {
	Host  string // host name or address, without the port
	Port  string // "445" when the name gave none
	Share string
	Path  string // slash separated, no leading or trailing slash; "" is the share root
}

// Bounds on what a name may hold. A path longer than this is refused before any
// byte goes on the wire.
const (
	maxNameLen  = 4096
	maxPathDeep = 256
)

// Addr is the host:port to dial.
func (t Target) Addr() string { return net.JoinHostPort(t.Host, t.Port) }

// ParseUNC reads //host[:port]/share[/path] (backslashes are accepted too).
// ".." and "." components, NUL and control characters are refused: the client
// never lets a name climb out of the share.
func ParseUNC(s string) (Target, error) {
	if len(s) > maxNameLen {
		return Target{}, errors.New("name too long")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return Target{}, errors.New("name holds a control character")
		}
	}
	s = strings.ReplaceAll(s, `\`, "/")
	if !strings.HasPrefix(s, "//") {
		return Target{}, fmt.Errorf("%q: want //host/share[/path]", s)
	}
	parts := strings.Split(s[2:], "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return Target{}, fmt.Errorf("%q: want //host/share[/path]", s)
	}
	t := Target{Port: "445"}
	hostport := parts[0]
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		if h == "" || p == "" {
			return Target{}, fmt.Errorf("%q: empty host or port", hostport)
		}
		t.Host, t.Port = h, p
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		t.Host = hostport[1 : len(hostport)-1]
	} else if strings.ContainsAny(hostport, "[]") {
		return Target{}, fmt.Errorf("%q: bad host", hostport)
	} else if strings.Contains(hostport, ":") {
		return Target{}, fmt.Errorf("%q: bad host:port (an IPv6 address needs [brackets])", hostport)
	} else {
		t.Host = hostport
	}
	if t.Host == "" {
		return Target{}, errors.New("empty host")
	}
	t.Share = parts[1]
	if t.Share == "." || t.Share == ".." {
		return Target{}, errors.New("bad share name")
	}
	var keep []string
	for _, c := range parts[2:] {
		switch c {
		case "", ".":
			continue
		case "..":
			return Target{}, errors.New(`".." is not allowed in a path`)
		}
		keep = append(keep, c)
	}
	if len(keep) > maxPathDeep {
		return Target{}, errors.New("path too deep")
	}
	t.Path = strings.Join(keep, "/")
	return t, nil
}
