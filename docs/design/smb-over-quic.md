# SMB 3.1.1 over QUIC — design

Status: **design, not implemented.** Tracks issue #68.

Goal: serve SMB 3.1.1 to Windows 11 and Samba clients over QUIC (TLS 1.3 on
UDP 443), so that a deployment exposes **no TCP 445** to the internet and
authenticates with Kerberos (through a KDC proxy, MS-KKDCP) rather than
passwords.

## 1. What the specifications say

Every reference below was opened for this document.

| Source | What it fixes |
|---|---|
| [MS-SMB2] §2.1 Transport (rev. 88.0, 2026-09-28) | "SMB2 dialect 3.1.1 allows operation over QUIC transport [RFC9000]." The 4-byte Direct TCP header (zero byte + 24-bit length) is the framing. |
| [MS-SMB2] §2.2.3.1.5 SMB2_TRANSPORT_CAPABILITIES (context type `0x0006`) | `Flags` (4 bytes); `SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY = 0x00000001`: "Transport security is offered to skip SMB2 encryption on this connection." |
| [MS-SMB2] §3.3.5.4 Receiving an SMB2 NEGOTIATE Request | A context shorter than its structure → `STATUS_INVALID_PARAMETER`. "If the underlying connection is over QUIC, DisableEncryptionOverSecureTransport is TRUE and SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY is set … the server MUST set Connection.AcceptTransportSecurity to TRUE", and the response context carries the same flag. **"If the common dialect is SMB 2.1 or 3.x and the underlying connection is either TCP port 445 or RDMA, Connection.SupportsMultiCredit MUST be set to TRUE; otherwise, it MUST be set to FALSE"** — and LARGE_MTU is advertised only with multi-credit. |
| [MS-SMB2] §3.3.1.7 Per Transport Connection | `Connection.AcceptTransportSecurity`, `Connection.TransportName`, `Connection.ServerCertificateMappingEntry` (§3.3.1.17, "used in QUIC connection establishment"). |
| IANA TLS ALPN registry | `SMB2` → `0x73 0x6D 0x62` (`"smb"`). |
| Microsoft Learn, *SMB over QUIC* (2025-07-24) | TLS 1.3 over UDP/443; block TCP/445 inbound. Client: Windows 11 (any build); `NET USE … /TRANSPORT:QUIC`, `New-SmbMapping -TransportType QUIC`. Certificate: digital-signature key usage, EKU Server Authentication, SHA-256+, ECDSA P-256+ or RSA 2048+, a DNS SAN per name, a Subject CN, **no IP SAN** (an IP forces NTLM). KDC Proxy is "supported … and highly recommended" (GPO *Specify KDC proxy servers for Kerberos clients*). Signing works normally. |
| Microsoft Learn, *Configure alternative SMB ports* | A non-443 QUIC port needs **Windows 11 24H2+ and admin rights** on the client (`/QUICPORT:<n>`, `-QuicPort`). |
| Microsoft Learn, *SMB over QUIC client access control* | Client certificate with EKU Client Authentication; server allow/deny by leaf SHA-256 or by issuer, any deny wins (`Set-SmbServerCertificateMapping -RequireClientAuthentication $true`). Client: 24H2+. |
| Samba 4.23.0 release notes (2025-09-12) | `server smb transports = +quic` (smbd, needs the out-of-tree `quic.ko`), `client smb transports` (userspace ngtcp2 fallback), name-based UNC only. → `smbclient` 4.23 is an interop oracle, `smbd` a performance comparator. |
| RFC 9000 | §8.1 anti-amplification (≤ 3× bytes received before validation), §8.1.2 Retry, §4.6 stream limits, §5.1.1 connection IDs, §21.2–21.9 DoS considerations (handshake, amplification, slowloris, stream fragmentation and commitment, peer DoS). |
| TrustedSec, *ntlmquic* | Empirical: a quic-go relay with ALPN `smb` that accepts **one bidirectional stream** per connection and copies its bytes to TCP 445 unchanged works with the Windows client. |

RFC 9001 was not opened; this design needs nothing from it beyond what quic-go
implements (0-RTT is off, §3).

## 2. Architecture in this library

The SMB byte stream over QUIC is the Direct TCP stream, unchanged, on the
connection's first client-initiated bidirectional stream. So the transport is
an adapter, and the session layer does not move:

- `frame.go` — `readFrame`/`writeFrame` serve QUIC as they are.
- `server.go:383` `Serve(ln net.Listener)` — the accept loop, backoff,
  `newConn` (`:529`) and `admit` stay; `serve()` (`:568`) uses
  `SetReadDeadline` and `io.ReadFull`, which a stream adapter provides.
- New file `transport_quic.go`:

```go
// ListenQUIC listens on UDP addr and returns a net.Listener whose Accept
// yields one net.Conn per QUIC connection: its first bidirectional stream,
// with RemoteAddr the client's UDP address.
func ListenQUIC(addr string, tlsConf *tls.Config, opts ...QUICOption) (net.Listener, error)
```

  The returned `net.Conn` carries a marker (an unexported interface or type
  assertion in `newConn`) so the connection knows `TransportName = "quic"`.
  `Close` closes the stream **and** the QUIC connection with an application
  error code; the read deadline maps to the stream's.

- `negctx.go` gains `SMB2_TRANSPORT_CAPABILITIES (0x0006)`: parsed only on a
  QUIC connection, `DataLength < 4` → `STATUS_INVALID_PARAMETER`, response
  flag set only when the server option `DisableEncryptionOverSecureTransport`
  (default **false**) is on. Default: SMB 3.1.1 encryption and signing stay
  on top of TLS — defence in depth, measured cost in §6.
- `SupportsMultiCredit`: by the letter of §3.3.5.4 it is FALSE over QUIC, so
  no LARGE_MTU. The implementation follows the letter first and records what
  Windows 11 actually sends in interop (§5); deviating needs that evidence.
- `limits.go` keys (`DefaultMaxConnectionsPerSource`, pre-auth limits) work
  unchanged because `RemoteAddr` is the real UDP source.

### QUIC configuration (quic-go v0.64.1 names, read from the module)

| Setting | Value | Why |
|---|---|---|
| TLS | 1.3 only, `NextProtos = ["smb"]` | MS-SMB2 + IANA; anything else is refused at the handshake |
| `Allow0RTT` | false; `Listen`, not `ListenEarly` | no replayable SMB NEGOTIATE / SESSION_SETUP |
| `MaxIncomingStreams` | 1 | one SMB stream per connection; a second is a protocol error |
| `MaxIncomingUniStreams` | -1 (none) | SMB uses none |
| `HandshakeIdleTimeout` | 5 s | RFC 9000 §21.2/§21.6 |
| `MaxIdleTimeout` | 60 s, `KeepAlivePeriod` 20 s | Windows keeps idle mounts |
| `MaxStreamReceiveWindow` / `MaxConnectionReceiveWindow` | bounded (start 16 MiB) | memory per connection is bounded; tuned by measurement |
| `Transport.VerifySourceAddress` | true above N handshakes in flight | Retry (RFC 9000 §8.1.2) only under load |

Client certificates (optional, `ClientAuth = RequireAndVerifyClientCert` plus
a leaf-SHA-256 / issuer allow-deny list) mirror Windows' client access
control.

### Dependency

quic-go (the fleet has no QUIC stack: `fleetverbs --match quic` found 0/128
packages). Pinned, and tracked by Renovate. It is behind a build tag
(`//go:build !noquic`) so a TCP-only build carries none of it.

## 3. fileshare

```hcl
serve "smb" {
  transport = "quic"           # "tcp" (default) or "quic"
  addr      = "0.0.0.0:443"    # UDP
  tls       = true             # allowed for smb ONLY with transport = "quic"
}
```

- `tls.go:87` `tlsProtocols` gains `smb` under that condition; `checkTLS`
  keeps refusing `tls` for smb over TCP.
- `tlsFor` appends ALPN `smb` (keeping `acme-tls/1` when ACME is on).
- `serve_smb.go:19` takes the listener from `smb.ListenQUIC` instead of
  `net.Listen("tcp")`.
- `check` warns when the certificate has an IP SAN only, or lacks a DNS SAN
  for the configured name (Windows would fall back to NTLM).

## 4. Port 443 on the production host

Caddy already serves HTTPS on TCP 443 and, by default, HTTP/3 on **UDP 443**
(the production Caddyfile sets no `protocols`). Windows only reaches port 443
for QUIC unless the client is 24H2+ with admin rights.

| Option | For | Against |
|---|---|---|
| **A. Caddy without h3** (`servers :443 { protocols h1 h2 }`), fileshare binds UDP 443 | any Windows 11, no admin, plain `\\name\share /TRANSPORT:QUIC`; real client address; no extra hop | browsers lose HTTP/3 and fall back to h2 transparently |
| B. Another UDP port | Caddy untouched | client 24H2+ **and admin** (`/QUICPORT`); site firewalls often block odd UDP ports |
| C. caddy-l4 `quic` matcher demux on UDP 443 | both on 443 | rejected: the matcher runs a throwaway quic-go handshake per probe (caddy-l4 v0.1.3 `modules/l4quic/matcher.go:122-144`, 100 ms window `:442`); the proxied UDP flow hides the client address from fileshare (no PROXY header quic-go can read), breaking per-source limits; connection migration breaks; the module calls itself experimental |
| D. A second public IP | no trade-off | needs an address |

**Recommendation: A** (or D if an address is available).

## 5. Tests

- Unit: the adapter (deadlines, close, second stream refused, uni stream
  refused); negotiate context `0x0006` (absent, short `DataLength`, flag
  on/off, ignored over TCP).
- Fuzz (corpus committed): `FuzzTransportCaps`; the QUIC stream path reuses
  `FuzzReadFrame`.
- Bomb/flood, under `GOMEMLIMIT` and `ulimit -v`, asserting refusals:
  Initial floods (Retry engages), stream-open floods, a peer that never
  reads (bounded windows), slowloris handshakes.
- Interop: Windows 11 fresh VM — `NET USE … /TRANSPORT:QUIC`, Kerberos via
  KKDCP, signing, encryption on and off with `0x0006`, record whether it
  asks for LARGE_MTU/multi-credit; Samba 4.23 `smbclient` with
  `client smb transports = quic`.

## 6. Performance

Single core, interleaved rounds, never at 1-min load > 8: read/write
throughput and small-op latency, QUIC vs TCP on this server, then vs Samba
4.23 smbd over QUIC (the reference). Separate rows for SMB encryption on and
off (`0x0006`). A gap is an open defect.

## 7. Security

UDP amplification (RFC 9000 §8.1, quic-go enforces it), Retry under load,
bounded windows and timeouts, no 0-RTT, single stream, per-source limits on
the real address, certificate without IP SAN, govulncheck on quic-go. QUIC
replaces the TCP 445 exposure: TCP 445 is closed in nftables in production.

## 8. Rollout

local → staging (157.136.254.110) → production (157.136.250.7), with TCP 445
closed and UDP 443 opened in nftables and the site firewall.

## 9. Open questions (for the operator)

1. May Caddy's HTTP/3 be dropped on production (option A)?
2. The SMB host name (e.g. `smb.mesocentre.plateau-de-saclay.net`, new A
   record, `cifs/` principal in kdcd).
3. Certificate source: Caddy's ACME storage read by fileshare (file ACL);
   fileshare's own ACME (needs a pre-validated HARICA account, since TCP
   443/80 belong to Caddy); or static files reloaded on change.
4. Client certificates: required or optional?
5. Minimum Windows 11 build (only matters for option B / client access
   control).
6. Are UDP 443 inbound open on the staging and production firewalls?
7. Is a second public IP available (option D)?
