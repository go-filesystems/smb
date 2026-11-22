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

RFC 9001 (opened for §4.1): §5.2 Initial secrets, derived from the client's
Destination Connection ID; §5, Initial packets have no confidentiality or
integrity protection; §4.3, a ClientHello may span several Initial packets.
haproxy `proxy-protocol.txt` (opened for §4.1): §2.2 DGRAM, `0x12` and `0x22`.

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

### Decisions (operator, 2026-11-22)

- **Host name:** `files.mesocentre.plateau-de-saclay.net`. This means a DNS A record, a `cifs/files.mesocentre.plateau-de-saclay.net` principal in kdcd and in fileshare's keytab, and a Caddy site block for that name so that Caddy obtains and renews the certificate.
- **Certificate:** from **Caddy's ACME storage**. fileshare reads the PEM files Caddy writes for that name with `cert_file` and `key_file`, which go-authn/servercert already reloads on change. fileshare's user gets read access to those two files only, through a file ACL. fileshare runs no ACME of its own, so the challenge stays with Caddy on TCP 443.
- **Client certificates: both modes, by configuration:**

  ```hcl
  serve "smb" {
    transport      = "quic"
    tls            = true
    client_cert    = "none"        # Kerberos only (default)
    # client_cert  = "required"    # Kerberos AND a client certificate
    client_ca_file = "/etc/fileshare/tls/smb-clients.pem"   # with "required"
    # optional allow/deny by leaf SHA-256 or issuer, as Windows does
  }
  ```

  - `required` means `tls.RequireAndVerifyClientCert`, checked against `client_ca_file` and an optional allow/deny list. A deny anywhere in the chain wins, mirroring `Set-SmbServerCertificateMapping -RequireClientAuthentication`.
  - The certificate gates the **transport** only. The person is still identified by Kerberos at SESSION_SETUP. Mapping a certificate to a user is out of scope.
  - `checkTLS` refuses `client_cert = "required"` without a CA file, and any `client_cert` without `transport = "quic"`.
  - On the client this needs Windows 11 24H2 or later (`New-SmbClientCertificateMapping`). That build floor applies only to the `required` mode.

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

This table was superseded on 2026-11-22: the operator asked for UDP 443 to be
shared by host name, which §4.1 evaluates.

### 4.1 UDP 443 demux by SNI

**Why it can be done without terminating TLS.** QUIC Initial packets are
encrypted with keys anyone can compute. RFC 9001 §5.2 derives them from the
client's Destination Connection ID with a published salt, and RFC 9001 §5
says Initial packets "are not considered to have confidentiality or
integrity protection". A front end can therefore:

1. remove header protection and decrypt the client's Initials;
2. reassemble the CRYPTO frames;
3. parse the ClientHello for SNI and ALPN (`smb` or `h3`);
4. pin the flow to a backend.

The front end never holds a certificate.

**Multi-packet ClientHello (checked against sources I opened):**

- RFC 9001 §4.3 anticipates the case: "If the ClientHello spans multiple Initial packets", servers have to buffer the fragments.
- Go itself, reading the go1.27.4 sources:
  - The default key exchanges include X25519MLKEM768 (`crypto/tls/common.go:813`, `defaults.go:40`).
  - Its key share is 1184 + 32 = **1216 bytes**: `mlkem768.go:57,60` gives the encapsulation key as `k*encodingSize12 + 32` with k = 3 and `encodingSize12 = 384`, and the X25519 share adds 32 bytes.
  - That alone exceeds the payload of an Initial packet sent in a 1200-byte datagram, so a default Go or quic-go ClientHello always spans at least two Initials.
- quic-go's client also **scrambles** its ClientHello. `crypto_stream.go:101-160` cuts the CRYPTO data around the SNI and ECH extensions (`findSNIAndECH`) and sends the pieces as separate frames. A demuxer must therefore reassemble out-of-order CRYPTO frames across packets, not read the first frame.
- I did **not** open a source for what browsers or Windows (Schannel/MsQuic) send. Treat "they also span two Initials" as likely, and capture it in interop before relying on it.

**Prior art:**

- quic-go has all the pieces, but every one is `internal/` and cannot be imported: `internal/handshake/initial_aead.go:28` `NewInitialAEAD`, `internal/wire/header.go:134` `ParsePacket`, and the frame parser.
- The fleet has none: `fleetverbs --match quic` and `--match sni` found 0 of 128 packages.
- caddy-l4 v0.1.3 has a `quic` matcher. It gets SNI and ALPN by running a full throwaway quic-go server handshake per probe (`modules/l4quic/matcher.go:122-144`, with a 100 ms window at `:442`). That matcher is unchanged on caddy-l4 master `1353123`.

The parsing (Initial v1 → decrypt → CRYPTO reassembly → ClientHello SNI and ALPN, with bounded buffers and no panics) belongs in **one new fleet Go package**. It is fuzzed, and both a stand-alone demuxer and a Caddy matcher can use it. Two notes on scope:

- Other QUIC versions use other salts (RFC 9001 §5.2), so a version the package does not know falls through to Caddy.
- The ClientHello is parsed with `golang.org/x/crypto/cryptobyte`. The standard library exposes no ClientHello parser.

**Routing after the handshake:**

- Flows are keyed by the client's address and port: the 4-tuple, as seen from our socket.
- **Connection migration and NAT rebinding** reach the demuxer from a new 4-tuple, starting with short-header packets that have no ClientHello. A plain 4-tuple router sends them to the default backend (Caddy), and the SMB connection drops. The Windows client then reconnects; its Kerberos ticket is cached, so re-authentication costs no KDC round trip.
- The fix is a **server-chosen connection ID** that fileshare marks. quic-go's `Transport.ConnectionIDGenerator` (`transport.go:84-86`) lets fileshare issue CIDs that carry a keyed tag. The router then sends a short-header packet whose DCID verifies to fileshare, and everything else to Caddy.
- Caddy's CIDs cannot be marked this way, so Caddy keeps the default. Its migrations are lost only when its own CIDs collide with the tag, which happens with probability 2^-tag-bits.

**Client address at the backends:**

- **fileshare:** we control it. It reads a header in front of each datagram from the loopback proxy, through a `net.PacketConn` wrapper handed to quic-go (`Transport.Conn`, `transport.go:73`), so `RemoteAddr` and the per-source limits see the real client. The wrapper:
  - accepts that header only from the configured proxy source;
  - maps each client address back to the proxy socket for `WriteTo`.
- **PROXY protocol v2:** it defines the DGRAM transport, UDP over IPv4 `0x12` and IPv6 `0x22` (haproxy `proxy-protocol.txt` §2.2). It says nothing about whether the header goes once or on every datagram; its only rule is "at the beginning of each connection" (§2). caddy-l4 chose to prepend it to **every** datagram (`modules/l4proxy/proxy.go:238-255`, `packetProxyProtocolConn`). fileshare would accept that form.
- **Caddy h3:** `http3.Server` takes no PROXY header over UDP. With a separate demuxer, Caddy would see every h3 client as 127.0.0.1, which blinds its logs and limits.
- **Alt-Svc from a loopback port:** Caddy binds h3 on the same address as the HTTPS server (`modules/caddyhttp/server.go:1072-1100`) and never sets `http3.Server.Port`. quic-go then derives the Alt-Svc port from the listener (`http3/server.go:388-423`). An h3 listener moved to a loopback port would therefore advertise that port: it would need a second Caddy server plus a hand-written `Alt-Svc` header. I have not tried this.

**Cost and DoS:**

- Passive parsing costs one HKDF per new DCID, one AES header-protection mask and one AES-GCM open per Initial (microseconds), against today's full handshake per probe.
- State per flow is a small buffer, capped at 3 Initials or 4 KiB, with a cap on flows still pending and a matching timeout. Above the caps, flows fall through to Caddy.
- The front end never answers by itself, so it adds **no amplification**. Amplification limits (RFC 9000 §8.1) and Retry stay with the backends.
- The parser faces every UDP 443 packet before any authentication. It must never panic: it is fuzzed (corpus committed) and bounded in both memory and time.
- Added latency is only the wait for the ClientHello's last Initial, which the client sends back to back, plus one loopback copy per SMB datagram. It needs measuring.

**caddy-l4 as the demuxer (the operator's "fix caddy-l4"):** caddy-l4 already has the rest of the machinery.

- `caddy.packetconns.layer4` (`layer4/packetconn.go:65-91`) wraps **Caddy's own HTTP/3 UDP socket**. Caddy's Caddyfile accepts `packet_conn_wrappers` (`caddyconfig/httpcaddyfile/serveroptions.go:113`). The wrapper splits the socket into flows by client address and port, runs the layer4 routes on each, and **releases the flows no route matches to Caddy's h3 server, with their original client address** (`:138-154`, a fallback connection).
- A route that matches `smb` can `proxy` with `proxy_protocol v2` to fileshare's loopback UDP port.
- Caddy h3 therefore keeps UDP 443 and the real addresses, and only SMB flows take the extra hop.
- What has to change is the matcher. Replace its throwaway handshake with the passive parser above, and feed the parser's SNI and ALPN to the existing tls matchers.
- "Experimental" is the label of the whole project (README line 4: "an experimental layer 4 app for Caddy"), not a caveat about UDP. The `l4quic` sources carry none.
- Flow state: the default `idle_timeout` is 30 s (`layer4/server.go:35`, applied at `packetconn.go:46-48`). For SMB it must exceed twice fileshare's QUIC `KeepAlivePeriod`, so set it to 120 s. Flows are keyed by 4-tuple, so migration needs the CID tag above, implemented in the matcher.
- The matcher ships first as **our own Caddy module**, with its own module ID, compiled by xcaddy next to the pinned caddy-l4. It is not a fork. Offering it upstream is the operator's decision.

| Option | Clients | h3 | SMB client address | Migration | New code / risk |
|---|---|---|---|---|---|
| A. Drop h3 | any Win 11, no admin | lost (browsers fall back to h2) | native | native | none |
| B. Other UDP port | 24H2+ **and** admin | kept | native | native | none; odd UDP ports often blocked |
| D. Second public IP | any | kept | native | native | none; needs an address |
| E. Our own UDP demuxer in front | any | kept, but Caddy sees 127.0.0.1 and Alt-Svc needs a second Caddy server | PROXY v2 per datagram | with the CID tag | new internet-facing daemon; extra hop for **all** h3 traffic |
| F. caddy-l4 `packet_conn_wrappers` + our passive QUIC matcher | any | kept, real addresses, no hop | PROXY v2 per datagram | with the CID tag | shared parsing package, Caddy module, fileshare PROXY reader; SMB depends on Caddy staying up |

**Recommendation: F, delivered in two steps.**

1. Ship SMB over QUIC with **A**. The fileshare QUIC listener is the same code either way.
2. Switch to **F** once the passive parser is fuzzed and measured. This restores h3 without moving it.

D replaces both steps if a second address appears.

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

Answered on 2026-11-22: the host name, the certificate source and the client-certificate modes (§3 Decisions), and UDP 443 shared by name (§4.1).

Still open:

1. May Caddy's HTTP/3 be dropped **for the interim** (§4.1, step 1)?
2. Are UDP 443 inbound open on the staging and production firewalls?
3. Is a second public IP available (option D)?
4. In the `required` mode, which CA issues the client certificates?
