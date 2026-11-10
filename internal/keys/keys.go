// Package keys generates the two key types the WARP API accepts:
// curve25519 (WireGuard) and secp256r1 (MASQUE, used for a self-signed
// TLS client certificate).
package keys

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

type WireGuard struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

func NewWireGuard() (*WireGuard, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &WireGuard{
		Private: base64.StdEncoding.EncodeToString(k.Bytes()),
		Public:  base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()),
	}, nil
}

// B64ToHex converts a base64 WireGuard key to the hex form wireguard-go's
// UAPI expects.
func B64ToHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) != 32 {
		return "", errors.New("wireguard key must be 32 bytes")
	}
	return hex.EncodeToString(b), nil
}

// NewECDSA returns a PEM-encoded P-256 private key.
func NewECDSA() (string, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

func ParseECDSA(p string) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil, errors.New("invalid ECDSA PEM")
	}
	return x509.ParseECPrivateKey(b.Bytes)
}

// ECDSAPublicPKIX returns base64(PKIX DER) of the public key, the format the
// API expects for key_type=secp256r1 (the official client shows the same
// SPKI encoding in `warp-cli registration show`).
func ECDSAPublicPKIX(p string) (string, error) {
	k, err := ParseECDSA(p)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}
