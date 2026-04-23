// Package oidc holds OIDC protocol primitives (keys, JWTs, PKCE, claims,
// discovery, JWKS, refresh-store) — HTTP-free so they can be unit-tested
// without a server.
package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/abdo75/Schlass/internal/crypto"
)

// 2048 is the NIST floor for new deployments and matches our 15-minute AT
// TTL — even if 2048 were cracked later, our tokens have long expired.
const RSAKeyBits = 2048

func GenerateKeyPair() (publicPEM, privatePEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc: rsa generate: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc: marshal pub: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return pubPEM, privPEM, nil
}

// signingKeyAAD prevents a wrapped private key from being swapped into
// another encrypted column (e.g. a user's TOTP secret). Static rather than
// per-kid because Insert generates the kid after WrapPrivateKey runs.
var signingKeyAAD = []byte("signing_key:private_pem")

func WrapPrivateKey(privatePEM, kek []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("oidc: kek must be 32 bytes, got %d", len(kek))
	}
	return crypto.Encrypt(privatePEM, kek, signingKeyAAD)
}

func UnwrapPrivateKey(wrapped, kek []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("oidc: kek must be 32 bytes, got %d", len(kek))
	}
	return crypto.Decrypt(wrapped, kek, signingKeyAAD)
}

func ParsePrivatePEM(privatePEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privatePEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("oidc: invalid private PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func ParsePublicPEM(publicPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("oidc: invalid public PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("oidc: public PEM is not RSA")
	}
	return rsaPub, nil
}
