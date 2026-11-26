package client

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Credentials is a user name, a password and an optional domain. It prints as
// "Credentials{user=…, password=<redacted>}" under every fmt verb, so a log
// line or an error that formats it cannot leak the password.
type Credentials struct {
	User     string
	Password string
	Domain   string
}

func (c Credentials) String() string {
	return "Credentials{user=" + c.User + ", domain=" + c.Domain + ", password=<redacted>}"
}

// GoString keeps %#v from printing the password.
func (c Credentials) GoString() string { return c.String() }

// maxCredentialsFile bounds what is read: a credentials file is a few lines.
const maxCredentialsFile = 4 << 10

// LoadCredentialsFile reads a mount.cifs style credentials file
// (username=, password=, domain=). The file is refused unless it is a regular
// file owned by the current user whose mode grants nothing to group or other
// (0600 or stricter). The checks run on the OPEN descriptor, so a swap between
// the check and the read cannot slip a different file in.
func LoadCredentialsFile(path string) (Credentials, error) {
	f, err := os.Open(path)
	if err != nil {
		return Credentials{}, fmt.Errorf("credentials file: %w", err)
	}
	defer f.Close()
	return readCredentials(f, path)
}

// openFile is what readCredentials needs of the open descriptor.
type openFile interface {
	io.Reader
	Stat() (os.FileInfo, error)
}

func readCredentials(f openFile, path string) (Credentials, error) {
	fi, err := f.Stat()
	if err != nil {
		return Credentials{}, fmt.Errorf("credentials file %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return Credentials{}, fmt.Errorf("credentials file %s: not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return Credentials{}, fmt.Errorf("credentials file %s: mode %04o grants access to group or other; chmod 600 it", path, fi.Mode().Perm())
	}
	if err := checkOwner(fi); err != nil {
		return Credentials{}, fmt.Errorf("credentials file %s: %w", path, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCredentialsFile+1))
	if err != nil {
		return Credentials{}, fmt.Errorf("credentials file %s: %w", path, err)
	}
	if len(data) > maxCredentialsFile {
		return Credentials{}, fmt.Errorf("credentials file %s: larger than %d bytes", path, maxCredentialsFile)
	}
	c, err := ParseCredentials(data)
	if err != nil {
		return Credentials{}, fmt.Errorf("credentials file %s: %w", path, err)
	}
	return c, nil
}

// LoadSystemdCredential reads $CREDENTIALS_DIRECTORY/name, the file systemd
// puts in front of a unit that has LoadCredentialEncrypted= (or LoadCredential=).
// Its content is the same key=value format, and the same mode and owner checks
// apply. name must be a plain file name.
func LoadSystemdCredential(name string) (Credentials, error) {
	return loadSystemdCredential(name, os.Getenv("CREDENTIALS_DIRECTORY"))
}

func loadSystemdCredential(name, dir string) (Credentials, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`+"\x00") {
		return Credentials{}, fmt.Errorf("credential name %q: must be a plain file name", name)
	}
	if dir == "" {
		return Credentials{}, errors.New("credential: CREDENTIALS_DIRECTORY is not set (run under systemd with LoadCredentialEncrypted=)")
	}
	return LoadCredentialsFile(filepath.Join(dir, name))
}

// ParseCredentials parses mount.cifs format: one key=value per line, '#' and
// ';' start a comment line, a value runs to the end of the line (a password may
// hold spaces and '='). Keys: username (or user), password (or pass), domain
// (or workgroup). An unknown or repeated key is an error; the message names the
// line and the key, never the value.
func ParseCredentials(data []byte) (Credentials, error) {
	var c Credentials
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1024), maxCredentialsFile)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' || trimmed[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return Credentials{}, fmt.Errorf("line %d: want key=value", n)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		switch k {
		case "user":
			k = "username"
		case "pass":
			k = "password"
		case "workgroup":
			k = "domain"
		}
		switch k {
		case "username", "password", "domain":
		default:
			return Credentials{}, fmt.Errorf("line %d: unknown key %q", n, k)
		}
		if seen[k] {
			return Credentials{}, fmt.Errorf("line %d: %s given twice", n, k)
		}
		seen[k] = true
		switch k {
		case "username":
			c.User = strings.TrimSpace(v)
		case "password":
			c.Password = v
		case "domain":
			c.Domain = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		return Credentials{}, fmt.Errorf("unreadable: %w", err)
	}
	if c.User == "" {
		return Credentials{}, errors.New("no username= line")
	}
	return c, nil
}
