package smb

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"
)

// unhex decodes hex, ignoring the spaces a published dump is wrapped with.
func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Known answers. [MS-SMB2] publishes no key-derivation vectors of its own, but
// the Open Specifications team published worked examples taken from real
// Windows exchanges, in the appendix "Key derivation examples" of
//
//	https://learn.microsoft.com/en-us/archive/blogs/openspecification/smb-2-and-smb-3-security-in-windows-10-the-anatomy-of-signing-and-cryptographic-keys
//
// (opened 2026-11-16; the post says its samples are "as-is" and that [MS-SMB2]
// is normative). They give the session key, the pre-authentication integrity
// hash and every derived key, so the derivation is checked against values this
// project did not compute.

// Example 1 and 2 of "Key derivation example for SMB 3.0 multichannel": a
// session key and the SigningKey derived from it (label "SMB2AESCMAC", context
// "SmbSign"), once for the master session and once for the second channel.
func TestSigningKeyKnownAnswers30(t *testing.T) {
	for _, tc := range []struct{ sessionKey, signingKey string }{
		{"7CD451825D0450D235424E44BA6E78CC", "0B7E9C5CAC36C0F6EA9AB275298CEDCE"},
		{"4E01A2B313BCF660CC250BEF021AEDE6", "BA1A17DBBFEC349BCA105563D598952F"},
	} {
		got := signingKeyFor(dialect300, unhex(t, tc.sessionKey), nil)
		if want := unhex(t, tc.signingKey); !bytes.Equal(got, want) {
			t.Errorf("session key %s: SigningKey %X, published %X", tc.sessionKey, got, want)
		}
		// 3.0.2 derives the same key as 3.0.
		if got := signingKeyFor(dialect302, unhex(t, tc.sessionKey), nil); !bytes.Equal(got, unhex(t, tc.signingKey)) {
			t.Errorf("3.0.2 differs from 3.0: %X", got)
		}
	}
}

// The two examples of "Key derivation example for SMB 3.1.1 multichannel":
// the SigningKey is the KDF of the session key with label "SMBSigningKey" and
// the final PreauthSession.PreauthIntegrityHashValue as context.
func TestSigningKeyKnownAnswers311(t *testing.T) {
	for _, tc := range []struct{ sessionKey, preauth, signingKey string }{
		{"270E1BA896585EEB7AF3472D3B4C75A7",
			"0DD13628CC3ED218EF9DF9772D436D0887AB9814BFAE63A80AA845F36909DB7928622DDDAD522D97" +
				"51640A459762C5A9D6BB084CBB3CE6BDADEF5D5BCE3C6C01",
			"73FE7A9A77BEF0BDE49C650D8CCB5F76"},
		{"84B9DBB730116A8FA6E9889555C265F9",
			"EA3BF912B11CBFEC5B1889E8209614218687F82FA5294521AD3063425E49E88A10BD022124CE2512" +
				"3BC9111F52D9566BA88BF46344E6063DC5E3FF0389026F6C",
			"C962BCA1A9DD1697B030644199705431"},
	} {
		pre := unhex(t, tc.preauth)
		if len(pre) != preauthHashSize {
			t.Fatalf("a preauth hash of %d bytes", len(pre))
		}
		got := signingKeyFor(dialect311, unhex(t, tc.sessionKey), pre)
		if want := unhex(t, tc.signingKey); !bytes.Equal(got, want) {
			t.Errorf("session key %s: SigningKey %X, published %X", tc.sessionKey, got, want)
		}
	}
}

// The first step of the published exchange: the pre-authentication hash after
// the NEGOTIATE request is SHA-512 over 64 zero bytes and the request exactly as
// it went on the wire.
func TestPreauthHashAgainstThePublishedNegotiate(t *testing.T) {
	req := unhex(t, "FE534D4240000100000000000000800000000000000000000100000000000000FFFE000000000000"+
		"00000000000000000000000000000000000000000000000024000500000000003F000000ECD86F32"+
		"6276024F9F7752B89BB33F3A70000000020000000202100200030203110300000100260000000000"+
		"010020000100FA49E6578F1F3A9F4CD3E9CC14A67AA884B3D05844E0E5A118225C15887F32FF0000"+
		"0200060000000000020002000100")
	want := unhex(t, "DD94EFC5321BB618A2E208BA8920D2F422992526947A409B5037DE1E0FE8C7362B8C47122594CDE0"+
		"CE26AA9DFC8BCDBDE0621957672623351A7540F1E54A0426")
	if got := preauthExtend(preauthStart(), req); !bytes.Equal(got, want) {
		t.Errorf("hash %X, published %X", got, want)
	}
	if sum := sha512.Sum512(append(make([]byte, 64), req...)); !bytes.Equal(sum[:], want) {
		t.Error("the published value is not SHA-512(0^64 || request)")
	}
}
