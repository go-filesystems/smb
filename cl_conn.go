// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
)

// The state machine of the in-house SMB 3.1.1 CLIENT engine ([MS-SMB2] 3.2).
//
// Scope of this increment, and why it is narrow on purpose: dialect 3.1.1 only
// (so the pre-authentication integrity hash protects the negotiate and
// VALIDATE_NEGOTIATE_INFO is never needed), NTLMv2 through SPNEGO, AES-GCM or
// AES-CCM encryption REQUIRED unless ClientOptions.AllowUnencrypted says
// otherwise, signing REQUIRED, and a bound on everything the server names.
// Kerberos, QUIC, the older dialects, compounding and the write paths beyond a
// whole-file write are the next increments.

// ErrEncryptionRequired is returned when encryption is required (the default)
// and the server cannot provide it.
var ErrEncryptionRequired = errors.New("smb: encryption is required and the server does not offer it")

// ClientOptions configure ClientDial.
type ClientOptions struct {
	User, Password, Domain string
	// Host is the server's name, for the SPN cifs/<Host> an NTLM exchange binds to.
	Host string
	// AllowUnencrypted turns OFF the requirement that every message after the
	// authentication is encrypted. Signing stays required either way.
	AllowUnencrypted bool
}

const (
	clCreditsWanted = 128
	clCreditsMax    = 1 << 16 // what a server can make us hold
	clMaxInterim    = 1 << 14 // STATUS_PENDING answers one request may draw
	clChunk         = 64 << 10
)

// ClientConn is one authenticated SMB 3.1.1 connection. It is safe for
// concurrent use: requests are multiplexed by MessageId.
type ClientConn struct {
	nc net.Conn
	o  ClientOptions

	wmu sync.Mutex // one frame at a time on the wire

	mu      sync.Mutex
	cond    *sync.Cond
	credits int
	nextID  uint64
	pending map[uint64]*clPending
	err     error // set once: the connection is dead
	sid     uint64

	dialect  uint16
	cipherID uint16
	sigAlg   sigAlgo
	caps     uint32
	maxTrans uint32
	maxRead  uint32
	maxWrite uint32
	preauth  []byte
	frameMax atomic.Int64

	ready     bool // the session is established: sign or encrypt
	encrypted bool // post-session messages are encrypted
	signKey   []byte
	enc, dec  cipher.AEAD
	nonces    atomic.Uint64

	done chan struct{}
}

type clPending struct {
	cmd     command
	ch      chan clResult
	verify  bool // the response must carry a valid signature
	wantEnc bool // the response must arrive encrypted
	interim int
}

type clResult struct {
	msg []byte // the whole plaintext message, header first
	h   header
	err error
}

// ClientDial negotiates, authenticates and returns a connection that signs
// (and, unless allowed otherwise, encrypts) everything after the
// authentication. It owns nc from here on.
func ClientDial(ctx context.Context, nc net.Conn, o ClientOptions) (*ClientConn, error) {
	if o.User == "" {
		return nil, errors.New("smb: no user name")
	}
	c := &ClientConn{nc: nc, o: o, credits: 1, pending: map[uint64]*clPending{}, done: make(chan struct{})}
	c.cond = sync.NewCond(&c.mu)
	c.frameMax.Store(clChunk + 4096) // until the negotiate says more
	go c.readLoop()
	if err := c.negotiate(ctx); err != nil {
		c.Close()
		return nil, err
	}
	if err := c.sessionSetup(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Dialect, CipherName and Encrypted report what was negotiated.
func (c *ClientConn) Dialect() uint16    { return c.dialect }
func (c *ClientConn) CipherName() string { return cipherName(c.cipherID) }
func (c *ClientConn) Encrypted() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.encrypted
}
func (c *ClientConn) Signing() string {
	switch c.sigAlg {
	case sigGMAC:
		return "AES-128-GMAC"
	case sigCMAC:
		return "AES-128-CMAC"
	}
	return "HMAC-SHA256"
}

// Close drops the connection; pending requests fail.
func (c *ClientConn) Close() error {
	c.fail(net.ErrClosed)
	err := c.nc.Close()
	<-c.done
	return err
}

func (c *ClientConn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
		for id, p := range c.pending {
			p.ch <- clResult{err: err}
			delete(c.pending, id)
		}
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	c.nc.Close()
}

// ─── the reader ──────────────────────────────────────────────────────────────

func (c *ClientConn) readLoop() {
	defer close(c.done)
	for {
		frame, err := readFrameMax(c.nc, int(c.frameMax.Load()))
		if err != nil {
			c.fail(err)
			return
		}
		if err := c.dispatch(frame); err != nil {
			c.fail(err)
			return
		}
	}
}

// dispatch checks one frame and hands it to the request it answers. An error
// ends the connection: a frame that breaks the rules is a server not to be
// talked to any further.
func (c *ClientConn) dispatch(frame []byte) error {
	enc := false
	if len(frame) >= 4 && [4]byte(frame[:4]) == transformProtocolID {
		c.mu.Lock()
		dec, sid := c.dec, c.sid
		c.mu.Unlock()
		if dec == nil || len(frame) <= transformLen || le16(frame[offTrFlags:]) != transformFlagOn || le64(frame[offTrSessionID:]) != sid {
			return errTransform
		}
		ct := frame[transformLen:]
		sealed := append(ct, frame[offTrSignature:offTrSignature+dec.Overhead()]...)
		plain, err := dec.Open(sealed[:0], frame[offTrNonce:offTrNonce+dec.NonceSize()], sealed, frame[offTrNonce:transformLen])
		if err != nil || int(le32(frame[offTrOrigSize:])) != len(plain) {
			return errTransform
		}
		frame, enc = plain, true
	}
	h, err := parseHeader(frame)
	if err != nil {
		return err
	}
	if h.flags&flagServerToRedir == 0 {
		return errors.New("smb: a message that is not a response")
	}
	if h.nextCommand != 0 {
		return errors.New("smb: compounded response to a request that was not")
	}
	if h.command == cmdOplockBreak && h.messageID == ^uint64(0) {
		return nil // an unsolicited break: no handle of ours can be open for a lease
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.credits = min(c.credits+int(h.credits), clCreditsMax)
	c.cond.Broadcast()
	if p := c.pending[h.messageID]; p != nil {
		return c.deliver(p, h, frame, enc)
	}
	return nil // an answer to nothing we wait for (a cancelled request)
}

// deliver hands a checked response to the request it answers; c.mu is held.
func (c *ClientConn) deliver(p *clPending, h header, frame []byte, enc bool) error {
	if h.command != p.cmd {
		return fmt.Errorf("smb: %s answered with %s", p.cmd, h.command)
	}
	if h.status == statusPending && h.flags&flagAsyncCommand != 0 {
		if p.interim++; p.interim > clMaxInterim {
			return errors.New("smb: the server keeps answering STATUS_PENDING")
		}
		return nil
	}
	if enc != p.wantEnc {
		return errors.New("smb: response protection differs from the request's (encryption is not negotiable down)")
	}
	if p.verify {
		if h.flags&flagSigned == 0 || !verifyMessage(c.sigAlg, c.signKey, frame) {
			return errors.New("smb: a response with a missing or wrong signature")
		}
	}
	delete(c.pending, h.messageID)
	p.ch <- clResult{msg: frame, h: h}
	return nil
}

// ─── sending ─────────────────────────────────────────────────────────────────

func creditCharge(n int) uint16 { return uint16(max(1, (n+clChunk-1)/clChunk)) }

// roundTrip sends one request and waits for its response. pre, when not nil, is
// a pre-authentication hash the request is folded into before it is sent and a
// response is folded into when it is not the last (or always, hashAll).
func (c *ClientConn) roundTrip(ctx context.Context, cmd command, tid uint32, charge uint16, bodyB []byte, pre *[]byte, hashAll bool) (clResult, error) {
	cost := max(int(charge), 1)
	stop := context.AfterFunc(ctx, func() { c.mu.Lock(); c.cond.Broadcast(); c.mu.Unlock() })
	defer stop()
	c.mu.Lock()
	for c.err == nil && ctx.Err() == nil && c.credits < cost {
		c.cond.Wait()
	}
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return clResult{}, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return clResult{}, err
	}
	c.credits -= cost
	id := c.nextID
	c.nextID += uint64(cost)
	sid := c.sid
	protect := c.ready && cmd != cmdNegotiate && cmd != cmdSessionSetup
	p := &clPending{cmd: cmd, ch: make(chan clResult, 1), verify: protect && !c.encrypted, wantEnc: protect && c.encrypted}
	c.pending[id] = p
	enc := c.enc
	c.mu.Unlock()

	frame := make([]byte, 4+headerLen, 4+headerLen+len(bodyB))
	msg := frame[4:]
	copy(msg, protocolID[:])
	binary.LittleEndian.PutUint16(msg[offStructSize:], headerLen)
	if cmd != cmdNegotiate {
		binary.LittleEndian.PutUint16(msg[offCreditCharge:], charge)
	}
	binary.LittleEndian.PutUint16(msg[offCommand:], uint16(cmd))
	binary.LittleEndian.PutUint16(msg[offCredits:], uint16(max(clCreditsWanted, 2*cost)))
	binary.LittleEndian.PutUint64(msg[offMessageID:], id)
	binary.LittleEndian.PutUint32(msg[offTreeID:], tid)
	binary.LittleEndian.PutUint64(msg[offSessionID:], sid)
	frame = append(frame, bodyB...)
	msg = frame[4:]
	switch {
	case p.wantEnc:
		frame = c.seal(enc, sid, msg)
	case p.verify:
		signMessage(c.sigAlg, c.signKey, msg)
	}
	if pre != nil {
		*pre = preauthExtend(*pre, msg)
	}
	binary.BigEndian.PutUint32(frame[:4], uint32(len(frame)-4))
	c.wmu.Lock()
	_, err := c.nc.Write(frame)
	c.wmu.Unlock()
	if err != nil {
		c.fail(err)
	}
	select {
	case r := <-p.ch:
		if r.err == nil && pre != nil && (hashAll || r.h.status == statusMoreProcessing) {
			*pre = preauthExtend(*pre, r.msg)
		}
		return r, r.err
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return clResult{}, ctx.Err()
	}
}

// seal builds the frame of an encrypted message: length, TRANSFORM_HEADER, the
// ciphertext. The tag goes in the header's Signature field ([MS-SMB2] 2.2.41).
func (c *ClientConn) seal(enc cipher.AEAD, sid uint64, plain []byte) []byte {
	out := make([]byte, 4+transformLen, 4+transformLen+len(plain)+enc.Overhead())
	t := out[4:]
	copy(t, transformProtocolID[:])
	binary.LittleEndian.PutUint64(t[offTrNonce:], c.nonces.Add(1))
	binary.LittleEndian.PutUint32(t[offTrOrigSize:], uint32(len(plain)))
	binary.LittleEndian.PutUint16(t[offTrFlags:], transformFlagOn)
	binary.LittleEndian.PutUint64(t[offTrSessionID:], sid)
	out = enc.Seal(out, t[offTrNonce:offTrNonce+enc.NonceSize()], plain, t[offTrNonce:transformLen])
	n := len(out) - enc.Overhead()
	copy(out[4+offTrSignature:], out[n:])
	return out[:n]
}

// ─── negotiate ───────────────────────────────────────────────────────────────

func (c *ClientConn) negotiate(ctx context.Context) error {
	var guid [16]byte
	rand.Read(guid[:])
	salt := make([]byte, 32)
	rand.Read(salt)
	ciphers := []uint16{cipherAES128GCM, cipherAES128CCM, cipherAES256GCM, cipherAES256CCM}
	signs := []uint16{signIDAESGMAC, signIDAESCMAC}
	ctxs, n := clContexts(salt, ciphers, signs)
	req := clNegotiateRequest([]uint16{dialect311}, signingEnabled|signingRequired, capLargeMTU, guid, ctxs, n)
	pre := preauthStart()
	r, err := c.roundTrip(ctx, cmdNegotiate, 0, 0, req, &pre, true)
	if err != nil {
		return err
	}
	if r.h.status != statusSuccess {
		return &StatusError{"NEGOTIATE", r.h.status}
	}
	nr, err := parseNegotiateResp(r.msg)
	if err != nil {
		return err
	}
	if nr.dialect != dialect311 {
		return fmt.Errorf("smb: the server chose dialect %#04x, which was not offered", nr.dialect)
	}
	sc, err := parseServerContexts(r.msg, nr.ctxOff, nr.ctxCount)
	if err != nil {
		return err
	}
	if sc.hash != hashIDSHA512 {
		return fmt.Errorf("smb: the server chose pre-authentication hash %#04x, which was not offered", sc.hash)
	}
	signID := signIDAESCMAC
	if sc.hasSign {
		if !slices.Contains(signs, sc.signing) {
			return fmt.Errorf("smb: the server chose signing algorithm %d, which was not offered", sc.signing)
		}
		signID = sc.signing
	}
	if sc.hasCipher && sc.cipher != cipherNone {
		if !slices.Contains(ciphers, sc.cipher) {
			return fmt.Errorf("smb: the server chose cipher %d, which was not offered", sc.cipher)
		}
		c.cipherID = sc.cipher
	}
	if c.cipherID == cipherNone && !c.o.AllowUnencrypted {
		return ErrEncryptionRequired
	}
	if nr.secMode&signingEnabled == 0 && nr.secMode&signingRequired == 0 {
		return errors.New("smb: the server does not sign")
	}
	c.mu.Lock()
	c.dialect, c.sigAlg, c.caps = dialect311, sigAlgoFor(dialect311, signID), nr.caps
	c.preauth = pre
	c.maxTrans, c.maxRead, c.maxWrite = nr.maxTrans, nr.maxRead, nr.maxWrite
	c.mu.Unlock()
	big := int64(max(nr.maxTrans, nr.maxRead, nr.maxWrite))
	c.frameMax.Store(min(max(big, clChunk), maxMessageLen) + 4096)
	return nil
}

// ─── session setup ───────────────────────────────────────────────────────────

func (c *ClientConn) sessionSetup(ctx context.Context) error {
	nt := newCLNTLM(c.o.User, c.o.Password, c.o.Domain, "cifs/"+c.o.Host)
	pre := slices.Clone(c.preauth)
	sec := signingEnabled | signingRequired
	r, err := c.roundTrip(ctx, cmdSessionSetup, 0, 1, clSessionSetupRequest(uint8(sec), spnegoInitToken(nt.type1())), &pre, false)
	if err != nil {
		return err
	}
	if r.h.status != statusMoreProcessing {
		return &StatusError{"SESSION_SETUP", r.h.status}
	}
	_, secBuf, err := parseSessionSetupResp(r.msg)
	if err != nil {
		return err
	}
	chalMsg, _, err := mechTokenOf(secBuf)
	if err != nil {
		return err
	}
	chal, err := parseChallenge(chalMsg)
	if err != nil {
		return err
	}
	auth, err := nt.authenticate(chalMsg, chal)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.sid = r.h.sessionID
	c.mu.Unlock()
	r, err = c.roundTrip(ctx, cmdSessionSetup, 0, 1, clSessionSetupRequest(uint8(sec), spnegoRespToken(auth)), &pre, false)
	if err != nil {
		return err
	}
	if r.h.status != statusSuccess {
		return &StatusError{"SESSION_SETUP", r.h.status}
	}
	flags, _, err := parseSessionSetupResp(r.msg)
	if err != nil {
		return err
	}
	if flags&0x3 != 0 { // IS_GUEST, IS_NULL: no session key, nothing to sign with
		return errors.New("smb: the server gave a guest or anonymous session, not an authenticated one")
	}
	key := signingKeyFor(dialect311, nt.exported, pre)
	// (a response that does not carry the signed flag cannot verify either: the
	// signature covers the flags)
	if !verifyMessage(c.sigAlg, key, r.msg) {
		return errors.New("smb: the final SESSION_SETUP response is not correctly signed")
	}
	var enc, dec cipher.AEAD
	if c.cipherID != cipherNone {
		bits := cipherKeyBits(c.cipherID)
		enc = mustAEAD(c.cipherID, kdf(nt.exported, "SMBC2SCipherKey\x00", string(pre), bits))
		dec = mustAEAD(c.cipherID, kdf(nt.exported, "SMBS2CCipherKey\x00", string(pre), bits))
	}
	c.mu.Lock()
	c.signKey, c.enc, c.dec = key, enc, dec
	c.encrypted = enc != nil && (!c.o.AllowUnencrypted || flags&sessionFlagEncryptData != 0)
	c.ready = true
	c.mu.Unlock()
	return nil
}

// mustAEAD builds the cipher of a negotiated id from a key the KDF sized for it.
// It can only fail on a mismatch between the two, which is a bug here and not
// something a server can cause.
func mustAEAD(id uint16, key []byte) cipher.AEAD {
	a, err := newCipherAEAD(id, key)
	if err != nil {
		panic("smb: client key schedule does not match the negotiated cipher: " + err.Error())
	}
	return a
}

// spnegoInitToken is the NegTokenInit that offers NTLMSSP with its first
// message as the optimistic mechToken (RFC 4178 4.2.1).
func spnegoInitToken(ntlm []byte) []byte {
	types := derCtx(0, derSeq(derOID(oidNTLMSSP)))
	tok := derCtx(2, derOctet(ntlm))
	init := derCtx(0, derSeq(append(types, tok...)))
	return derApp(0, append(derOID(oidSPNEGO), init...))
}

// spnegoRespToken is the NegTokenResp that carries the NTLM AUTHENTICATE.
func spnegoRespToken(ntlm []byte) []byte {
	return derCtx(1, derSeq(derCtx(2, derOctet(ntlm))))
}

// ─── tree connect ────────────────────────────────────────────────────────────

// ClientShare is a tree connect.
type ClientShare struct {
	c    *ClientConn
	tid  uint32
	name string
}

// Mount tree-connects share. A share that requires encryption switches the
// connection to it; one that the server cannot encrypt for is refused.
func (c *ClientConn) Mount(ctx context.Context, share string) (*ClientShare, error) {
	for _, r := range share {
		if r == '\\' || r == '/' || r == 0 {
			return nil, fmt.Errorf("smb: bad share name %q", share)
		}
	}
	r, err := c.roundTrip(ctx, cmdTreeConnect, 0, 1, clTreeConnectRequest(`\\`+c.o.Host+`\`+share), nil, false)
	if err != nil {
		return nil, err
	}
	if r.h.status != statusSuccess {
		return nil, &StatusError{"TREE_CONNECT", r.h.status}
	}
	t, err := parseTreeConnectResp(r.msg)
	if err != nil {
		return nil, err
	}
	if t.flags&shareFlagEncryptData != 0 {
		c.mu.Lock()
		if c.enc == nil {
			c.mu.Unlock()
			return nil, ErrEncryptionRequired
		}
		c.encrypted = true
		c.mu.Unlock()
	}
	return &ClientShare{c: c, tid: r.h.treeID, name: share}, nil
}

// Close disconnects the tree.
func (s *ClientShare) Close(ctx context.Context) error {
	_, err := s.c.roundTrip(ctx, cmdTreeDisconnect, s.tid, 1, clEmptyRequest(), nil, false)
	return err
}

// Logoff ends the session and drops the connection.
func (c *ClientConn) Logoff(ctx context.Context) error {
	_, err := c.roundTrip(ctx, cmdLogoff, 0, 1, clEmptyRequest(), nil, false)
	c.Close()
	return err
}

var _ = io.EOF
