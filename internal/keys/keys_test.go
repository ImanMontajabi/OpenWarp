package keys

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewWireGuardIsAValidX25519Pair(t *testing.T) {
	k, err := NewWireGuard()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := base64.StdEncoding.DecodeString(k.Private)
	if err != nil || len(priv) != 32 {
		t.Fatalf("private key must be 32 bytes of base64: %v (%d bytes)", err, len(priv))
	}
	sk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(sk.PublicKey().Bytes()); got != k.Public {
		t.Fatal("public key does not belong to the private key")
	}
	k2, _ := NewWireGuard()
	if k2.Private == k.Private {
		t.Fatal("two generated keys are identical")
	}
}

func TestB64ToHex(t *testing.T) {
	raw := make([]byte, 32)
	raw[0], raw[31] = 0xab, 0x01
	got, err := B64ToHex(base64.StdEncoding.EncodeToString(raw))
	if err != nil || got != hex.EncodeToString(raw) {
		t.Fatalf("B64ToHex = %q, %v", got, err)
	}
	for _, bad := range []string{"not base64!", base64.StdEncoding.EncodeToString(make([]byte, 31)), ""} {
		if _, err := B64ToHex(bad); err == nil {
			t.Errorf("B64ToHex(%q) accepted an invalid key", bad)
		}
	}
}

func TestECDSAIsP256AndPublicKeyIsPKIX(t *testing.T) {
	p, err := NewECDSA()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, "-----BEGIN EC PRIVATE KEY-----") {
		t.Fatalf("unexpected PEM type: %.40q", p)
	}
	k, err := ParseECDSA(p)
	if err != nil || k.Curve != elliptic.P256() {
		t.Fatalf("not a P-256 key: %v", err)
	}
	pub, err := ECDSAPublicPKIX(p)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := base64.StdEncoding.DecodeString(pub)
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("public key is not base64 PKIX DER: %v", err)
	}
	if !k.PublicKey.Equal(parsed) {
		t.Fatal("PKIX public key does not match the private key")
	}
}

func TestParseECDSARejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "hello", "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"} {
		if _, err := ParseECDSA(bad); err == nil {
			t.Errorf("ParseECDSA(%q) succeeded", bad)
		}
		if _, err := ECDSAPublicPKIX(bad); err == nil {
			t.Errorf("ECDSAPublicPKIX(%q) succeeded", bad)
		}
	}
}
