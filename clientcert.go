// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Client certificates for SMB over QUIC. Windows' "client access control"
// ([MS-SMB2] 3.3.1.17 and Microsoft Learn, SMB over QUIC client access control)
// asks the client for a certificate with EKU Client Authentication and checks it
// on the server. That gate is on the TRANSPORT only: the person is still
// identified by the SESSION_SETUP, with Kerberos.

// Bounds on a CA file: it is read before anything is authenticated, from a path
// an operator names, but a wrong path (a log, a disk image) must not be parsed to
// the end.
const (
	maxClientCAFileBytes = 1 << 20
	maxClientCACerts     = 64
)

// ErrNoClientCA is returned for a CA file with no certificate in it.
var ErrNoClientCA = errors.New("smb: the client CA file holds no certificate")

// ParseClientCAs reads a PEM bundle of CA certificates. It refuses a file with
// no certificate, one over 1 MiB, more than 64 certificates, a PEM block that is
// not a CERTIFICATE, and a certificate that does not parse, so a half-valid
// bundle never silently trusts less (or more) than the operator wrote.
func ParseClientCAs(pemBytes []byte) (*x509.CertPool, error) {
	if len(pemBytes) > maxClientCAFileBytes {
		return nil, fmt.Errorf("smb: the client CA file is %d bytes, over %d", len(pemBytes), maxClientCAFileBytes)
	}
	pool := x509.NewCertPool()
	n := 0
	for rest := pemBytes; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("smb: the client CA file has a %q block, not a CERTIFICATE", blk.Type)
		}
		crt, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("smb: the client CA file: %w", err)
		}
		if n++; n > maxClientCACerts {
			return nil, fmt.Errorf("smb: the client CA file has more than %d certificates", maxClientCACerts)
		}
		pool.AddCert(crt)
	}
	if n == 0 {
		return nil, ErrNoClientCA
	}
	return pool, nil
}

// RequireClientCertificate makes conf demand a client certificate that chains to
// one of the CAs in caPEM (tls.RequireAndVerifyClientCert; Go checks the EKU
// Client Authentication). A client with none, or one from another CA, is refused
// in the handshake, before a byte of SMB is read.
func RequireClientCertificate(conf *tls.Config, caPEM []byte) error {
	pool, err := ParseClientCAs(caPEM)
	if err != nil {
		return err
	}
	conf.ClientAuth = tls.RequireAndVerifyClientCert
	conf.ClientCAs = pool
	return nil
}
