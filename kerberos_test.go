package smb_test

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
	jasn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"

	fssmb "github.com/go-filesystems/smb"
)

// Kerberos in SPNEGO ([MS-SMB2] 3.3.5.5.3; RFC 4178; RFC 4121; [MS-KILE]).
//
// The judge is go-smb2's Krb5Initiator, which builds a real AP-REQ with gokrb5
// and reads the AP-REP the way a GSS-API client does; and the keys it signs with
// are the ones the acceptor returned, so a mismatch is a signature the server
// refuses. There is no KDC: the tickets are minted here, encrypted under a
// keytab the acceptor holds, and put in a credential cache the client reads.
// What a KDC would add (the TGS exchange) is not the server's business.

const (
	krbRealm = "EXAMPLE.ORG"
	krbSPN   = "cifs/fs.example.org"
)

var oidKerberos = jasn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
var oidMSKerberos = jasn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}

func keytabFor(t *testing.T, spn, secret string) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry(spn, krbRealm, secret, time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	return kt
}

// mint makes a service ticket for who, encrypted under kt's key for spn, and
// returns it with its session key.
func mint(t *testing.T, kt *keytab.Keytab, who, spn string, start, end time.Time) (messages.Ticket, types.EncryptionKey) {
	t.Helper()
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, who)
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn)
	tkt, key, err := messages.NewTicket(cname, krbRealm, sname, krbRealm, types.NewKrbFlags(), kt, 18, 1, start, start, end, end)
	if err != nil {
		t.Fatal(err)
	}
	return tkt, key
}

// krbClient is a gokrb5 client whose credential cache holds the one ticket.
func krbClient(t *testing.T, who string, tkt messages.Ticket, key types.EncryptionKey, start, end time.Time) *client.Client {
	t.Helper()
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, who)
	tgsKt := keytabFor(t, "krbtgt/"+krbRealm, "tgs-secret")
	tgt, tgtKey := mint(t, tgsKt, who, "krbtgt/"+krbRealm, start, end)
	add := func(cc *credentials.CCache, tk messages.Ticket, k types.EncryptionKey) {
		b, err := tk.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		cred := &credentials.Credential{Key: k, AuthTime: start, StartTime: start, EndTime: end, RenewTill: end, Ticket: b}
		cred.Client.Realm, cred.Client.PrincipalName = krbRealm, cname
		cred.Server.Realm, cred.Server.PrincipalName = krbRealm, tk.SName
		cc.Credentials = append(cc.Credentials, cred)
	}
	cc := &credentials.CCache{Version: 4}
	cc.DefaultPrincipal.Realm, cc.DefaultPrincipal.PrincipalName = krbRealm, cname
	add(cc, tgt, tgtKey)
	add(cc, tkt, key)
	cfg, err := config.NewFromString("[libdefaults]\n default_realm = " + krbRealm + "\n")
	if err != nil {
		t.Fatal(err)
	}
	cl, err := client.NewFromCCache(cc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

// testAcceptor is the keytab-backed Acceptor an embedder writes, over gokrb5. It
// answers with an AP-REP carrying an acceptor subkey, as MIT and Heimdal do, and
// returns that subkey as the context key (RFC 4121 section 2: the acceptor's subkey if it asserts one).
type testAcceptor struct {
	kt    *keytab.Keytab
	spn   string
	users map[string]string // principal -> the name the share sees
	skew  time.Duration

	mu     sync.Mutex
	tokens [][]byte
	errs   []string
}

func (a *testAcceptor) Accept(token []byte) (*fssmb.Accepted, []byte, error) {
	a.mu.Lock()
	a.tokens = append(a.tokens, bytes.Clone(token))
	a.mu.Unlock()
	acc, rep, err := a.accept(token)
	if err != nil {
		a.mu.Lock()
		a.errs = append(a.errs, err.Error())
		a.mu.Unlock()
	}
	return acc, rep, err
}

// lastRefusal is why the acceptor last refused: a refusal test that only sees the
// dial fail cannot tell the server's refusal from the client's own error.
func (a *testAcceptor) lastRefusal() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.errs) == 0 {
		return ""
	}
	return strings.ToLower(a.errs[len(a.errs)-1])
}

func (a *testAcceptor) accept(token []byte) (*fssmb.Accepted, []byte, error) {
	var tok spnego.KRB5Token
	if err := tok.Unmarshal(token); err != nil {
		return nil, nil, err
	}
	if !tok.IsAPReq() {
		return nil, nil, errors.New("not an AP-REQ")
	}
	skew := a.skew
	if skew == 0 {
		skew = 5 * time.Minute
	}
	ok, creds, err := service.VerifyAPREQ(&tok.APReq, service.NewSettings(a.kt,
		service.KeytabPrincipal(a.spn), service.MaxClockSkew(skew), service.DecodePAC(false)))
	if err != nil || !ok {
		return nil, nil, errors.Join(errors.New("ticket rejected"), err)
	}
	principal := creds.UserName() + "@" + creds.Domain()
	user, known := a.users[principal]
	if !known {
		return nil, nil, errors.New("unknown principal " + principal)
	}
	sess := tok.APReq.Ticket.DecryptedEncPart.Key
	et, err := crypto.GetEtype(sess.KeyType)
	if err != nil {
		return nil, nil, err
	}
	sub, err := types.GenerateEncryptionKey(et)
	if err != nil {
		return nil, nil, err
	}
	enc := messages.EncAPRepPart{CTime: tok.APReq.Authenticator.CTime, Cusec: tok.APReq.Authenticator.Cusec, Subkey: sub, SequenceNumber: 1}
	eb, err := jasn1.Marshal(enc)
	if err != nil {
		return nil, nil, err
	}
	eb = asn1tools.AddASNAppTag(eb, asnAppTag.EncAPRepPart)
	ed, err := crypto.GetEncryptedData(eb, sess, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return nil, nil, err
	}
	rb, err := jasn1.Marshal(messages.APRep{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REP, EncPart: ed})
	if err != nil {
		return nil, nil, err
	}
	rb = asn1tools.AddASNAppTag(rb, asnAppTag.APREP)
	oid, _ := jasn1.Marshal(gssapi.OIDKRB5.OID())
	rep := asn1tools.AddASNAppTag(append(append(oid, 0x02, 0x00), rb...), 0)
	return &fssmb.Accepted{
		User: user, Principal: principal, Key: sub.KeyValue,
		Expires: tok.APReq.Ticket.DecryptedEncPart.EndTime,
	}, rep, nil
}

// krbRig is a server with Kerberos, a keytab, and one ticket-holding client.
type krbRig struct {
	addr string
	srv  *fssmb.Server
	acc  *testAcceptor
	kt   *keytab.Keytab
}

func newRig(t *testing.T, mutate func(*fssmb.Server)) *krbRig {
	t.Helper()
	kt := keytabFor(t, krbSPN, "service-secret")
	acc := &testAcceptor{kt: kt, spn: krbSPN, users: map[string]string{"alice@" + krbRealm: "alice", "bob@" + krbRealm: "bob"}}
	srv := fssmb.New()
	srv.Kerberos = acc
	srv.RequireSigning = true
	if mutate != nil {
		mutate(srv)
	}
	if err := srv.Share("disk", newMemFS(true), fssmb.AllowUsers("alice")); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return &krbRig{addr: ln.Addr().String(), srv: srv, acc: acc, kt: kt}
}

// initiator is a Kerberos client for who, with a ticket valid now.
func (r *krbRig) initiator(t *testing.T, who string) *smb2.Krb5Initiator {
	t.Helper()
	start, end := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	tkt, key := mint(t, r.kt, who, krbSPN, start, end)
	return &smb2.Krb5Initiator{Client: krbClient(t, who, tkt, key, start, end), TargetSPN: krbSPN}
}

func dialWith(t *testing.T, addr string, in smb2.Initiator, dialect uint16) (*smb2.Session, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	d := &smb2.Dialer{Initiator: in, Negotiator: smb2.Negotiator{SpecifiedDialect: dialect, RequireMessageSigning: true}}
	return d.Dial(ctx, addr)
}

// A signed session, in every dialect: the client signs with the key the acceptor
// returned and the server verifies it, so a file written and read back proves the
// two ended up with the same key ([MS-SMB2] 3.3.5.5.3 steps 6 and 7).
func TestKerberosSessionIsSignedAndWorks(t *testing.T) {
	for _, d := range []struct {
		name    string
		dialect uint16
	}{{"3.1.1", 0}, {"3.0.2", 0x0302}, {"3.0", 0x0300}, {"2.1", 0x0210}} {
		t.Run(d.name, func(t *testing.T) {
			r := newRig(t, nil)
			s, err := dialWith(t, r.addr, r.initiator(t, "alice"), d.dialect)
			if err != nil {
				t.Fatalf("a Kerberos client was refused: %v", err)
			}
			defer s.Logoff()
			fs, err := s.Mount("disk")
			if err != nil {
				t.Fatalf("connecting to the share: %v", err)
			}
			defer fs.Umount()
			if err := fs.WriteFile("hello.txt", []byte("signed by a Kerberos key"), 0o644); err != nil {
				t.Fatalf("writing: %v", err)
			}
			got, err := fs.ReadFile("hello.txt")
			if err != nil || string(got) != "signed by a Kerberos key" {
				t.Fatalf("reading back: %q, %v", got, err)
			}
		})
	}
}

// The principal is mapped by the embedder, and the share's access rules see the
// mapped name: bob authenticates (Kerberos proved who he is) and the share, which
// allows only alice, refuses him. A principal the embedder does not know is not
// let in at all.
func TestKerberosUserIsWhatTheEmbedderMapped(t *testing.T) {
	r := newRig(t, nil)
	s, err := dialWith(t, r.addr, r.initiator(t, "bob"), 0)
	if err != nil {
		t.Fatalf("bob authenticates: %v", err)
	}
	defer s.Logoff()
	if fs, err := s.Mount("disk"); err == nil {
		fs.Umount()
		t.Error("the share let bob in, and it allows only alice")
	}

	if s, err := dialWith(t, r.addr, r.initiator(t, "mallory"), 0); err == nil {
		s.Logoff()
		t.Error("a principal the embedder does not know was let in")
	}
}

// A key that is not the one the client holds: the signature fails, so nothing
// works even though the AP-REQ was accepted. Without this a test could pass on a
// server that signs with any key at all.
func TestKerberosWrongKeyBreaksSigning(t *testing.T) {
	r := newRig(t, nil)
	r.srv.Kerberos = flipKey{r.acc}
	s, err := dialWith(t, r.addr, r.initiator(t, "alice"), 0)
	if err == nil {
		defer s.Logoff()
		fs, err := s.Mount("disk")
		if err == nil {
			defer fs.Umount()
			if err = fs.WriteFile("x", []byte("x"), 0o644); err == nil {
				t.Fatal("a session keyed differently from the client's signed and verified")
			}
		}
	}
}

type flipKey struct{ *testAcceptor }

func (f flipKey) Accept(tok []byte) (*fssmb.Accepted, []byte, error) {
	a, rep, err := f.testAcceptor.Accept(tok)
	if a != nil {
		a.Key[0] ^= 1
	}
	return a, rep, err
}

// A ticket for another service, or one this keytab cannot read, is refused with
// the same logon failure as everything else.
func TestKerberosWrongServiceIsRefused(t *testing.T) {
	r := newRig(t, nil)
	other := keytabFor(t, "cifs/other.example.org", "another-secret")
	start, end := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	tkt, key := mint(t, other, "alice", "cifs/other.example.org", start, end)
	in := &smb2.Krb5Initiator{Client: krbClient(t, "alice", tkt, key, start, end), TargetSPN: "cifs/other.example.org"}
	if s, err := dialWith(t, r.addr, in, 0); err == nil {
		s.Logoff()
		t.Error("a ticket for another service was accepted")
	}
	if why := r.acc.lastRefusal(); !strings.Contains(why, "rejected") {
		t.Errorf("the acceptor did not refuse it itself: %q", why)
	}
}

// An expired ticket, a replayed one, and a token that is no AP-REQ.
func TestKerberosRefusals(t *testing.T) {
	r := newRig(t, nil)
	now := time.Now()

	// Expired: the ticket's end was ten minutes ago, beyond the five of clock skew.
	start, end := now.Add(-time.Hour), now.Add(-10*time.Minute)
	tkt, key := mint(t, r.kt, "alice", krbSPN, start, end)
	cl := krbClient(t, "alice", tkt, key, start, end)
	exp := &rawInit{inner: &smb2.Krb5Initiator{Client: cl, TargetSPN: krbSPN}, forceTicket: &tkt, forceKey: &key, cl: cl}
	if s, err := dialWith(t, r.addr, exp, 0); err == nil {
		s.Logoff()
		t.Error("an expired ticket was accepted")
	}
	if why := r.acc.lastRefusal(); !strings.Contains(why, "expired") {
		t.Errorf("the acceptor did not refuse it as expired: %q", why)
	}

	// Replay: the AP-REQ a first connection used, sent again by a second.
	good := &rawInit{inner: r.initiator(t, "alice")}
	s, err := dialWith(t, r.addr, good, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.Logoff()
	again := &rawInit{inner: r.initiator(t, "alice"), replay: good.sent}
	if s, err := dialWith(t, r.addr, again, 0); err == nil {
		s.Logoff()
		t.Error("a replayed AP-REQ was accepted")
	}
	if why := r.acc.lastRefusal(); !strings.Contains(why, "replay") {
		t.Errorf("the acceptor did not refuse it as a replay: %q", why)
	}

	// Not an AP-REQ at all: a Kerberos OID around garbage.
	junk := &rawInit{inner: r.initiator(t, "alice"), replay: append([]byte{0x60, 0x0f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}, 0x01, 0x00, 0xff)}
	if s, err := dialWith(t, r.addr, junk, 0); err == nil {
		s.Logoff()
		t.Error("garbage behind the Kerberos OID was accepted")
	}
	if why := r.acc.lastRefusal(); why == "" {
		t.Error("the acceptor never saw the garbage")
	}
}

// rawInit lets a test choose the token and the OID the client announces.
type rawInit struct {
	inner       *smb2.Krb5Initiator
	oid         jasn1.ObjectIdentifier
	replay      []byte
	forceTicket *messages.Ticket
	forceKey    *types.EncryptionKey
	cl          *client.Client

	sent []byte
}

func (r *rawInit) OID() asn1.ObjectIdentifier {
	if r.oid != nil {
		return asn1.ObjectIdentifier(r.oid)
	}
	return r.inner.OID()
}

func (r *rawInit) InitSecContext() ([]byte, error) {
	var tok []byte
	var err error
	switch {
	case r.replay != nil:
		tok = r.replay
		// the inner initiator still needs its session key to read the AP-REP
		_, err = r.inner.InitSecContext()
	case r.forceTicket != nil:
		var t spnego.KRB5Token
		t, err = spnego.NewKRB5TokenAPREQ(r.cl, *r.forceTicket, *r.forceKey, []int{gssapi.ContextFlagMutual}, []int{flags.APOptionMutualRequired})
		if err == nil {
			tok, err = t.Marshal()
		}
	default:
		tok, err = r.inner.InitSecContext()
	}
	if err != nil {
		return nil, err
	}
	if r.oid != nil && len(tok) > 0 {
		tok = reframe(tok, r.oid)
	}
	r.sent = tok
	return tok, nil
}

// reframe rewrites the mechanism OID of a GSS-API InitialContextToken.
func reframe(tok []byte, oid jasn1.ObjectIdentifier) []byte {
	var cur jasn1.ObjectIdentifier
	rest, err := jasn1.UnmarshalWithParams(tok, &cur, "application,explicit,tag:0")
	if err != nil {
		panic(err)
	}
	o, _ := jasn1.Marshal(oid)
	return asn1tools.AddASNAppTag(append(o, rest...), 0)
}

func (r *rawInit) AcceptSecContext(sc []byte) ([]byte, error) {
	if r.oid != nil && len(sc) > 0 {
		// Windows frames the AP-REP in the OID it sent; go-smb2's reader wants the
		// standard one, so check ours and put the standard one back.
		var cur jasn1.ObjectIdentifier
		if _, err := jasn1.UnmarshalWithParams(sc, &cur, "application,explicit,tag:0"); err != nil || !cur.Equal(r.oid) {
			return nil, errors.New("the AP-REP is not framed with the OID the client used: " + cur.String())
		}
		sc = reframe(sc, oidKerberos)
	}
	return r.inner.AcceptSecContext(sc)
}
func (r *rawInit) Sum(b []byte) []byte { return r.inner.Sum(b) }
func (r *rawInit) SessionKey() []byte  { return r.inner.SessionKey() }

// Windows announces the Microsoft OID and frames its AP-REQ with it; the
// acceptor must see the standard one and the AP-REP must come back in the
// Microsoft one.
func TestKerberosMicrosoftOID(t *testing.T) {
	r := newRig(t, nil)
	in := &rawInit{inner: r.initiator(t, "alice"), oid: oidMSKerberos}
	s, err := dialWith(t, r.addr, in, 0)
	if err != nil {
		t.Fatalf("a client using MS-KRB5 was refused: %v", err)
	}
	defer s.Logoff()
	fs, err := s.Mount("disk")
	if err != nil {
		t.Fatal(err)
	}
	fs.Umount()
	r.acc.mu.Lock()
	defer r.acc.mu.Unlock()
	var oid jasn1.ObjectIdentifier
	if _, err := jasn1.UnmarshalWithParams(r.acc.tokens[0], &oid, "application,explicit,tag:0"); err != nil || !oid.Equal(oidKerberos) {
		t.Errorf("the acceptor was handed OID %v, want the standard one", oid)
	}
}

// With NTLM disabled the server offers only Kerberos, refuses an NTLM client,
// and still serves a Kerberos one. Without a Kerberos acceptor it will not start.
func TestKerberosOnlyServer(t *testing.T) {
	r := newRig(t, func(s *fssmb.Server) { s.DisableNTLM = true })
	r.srv.AddUser("alice", "hunter2")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "alice", Password: "hunter2"}}
	if s, err := d.Dial(ctx, r.addr); err == nil {
		s.Logoff()
		t.Fatal("NTLMSSP was accepted by a server with NTLM disabled")
	}
	s, err := dialWith(t, r.addr, r.initiator(t, "alice"), 0)
	if err != nil {
		t.Fatalf("Kerberos on a Kerberos-only server: %v", err)
	}
	s.Logoff()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	bad := fssmb.New()
	bad.DisableNTLM = true
	if err := bad.Serve(ln); !errors.Is(err, fssmb.ErrNeedKerberos) {
		t.Errorf("Serve with NTLM off and no acceptor returned %v, want ErrNeedKerberos", err)
	}
}

// Both mechanisms at once: an NTLM client is served by a server that also has
// Kerberos, and the NEGOTIATE response lists Kerberos ahead of NTLM.
func TestKerberosAndNTLMTogether(t *testing.T) {
	r := newRig(t, nil)
	r.srv.AddUser("carol", "pw")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "carol", Password: "pw"}}
	s, err := d.Dial(ctx, r.addr)
	if err != nil {
		t.Fatalf("NTLM on a server that also offers Kerberos: %v", err)
	}
	s.Logoff()
}
