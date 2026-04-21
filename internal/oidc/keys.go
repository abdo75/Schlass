// Package oidc contains OIDC protocol primitives (keys, JWTs, PKCE,
// claims, discovery, JWKS, refresh-store) that are intentionally
// HTTP-free so they can be unit-tested without a server.
package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/abdo75/Schlass/internal/crypto"
)

// rsaKeyBits is the RSA modulus size in bits. 2048 is the NIST-recommended
// floor for new deployments and matches the 15-minute access-token TTL —
// even if 2048 were cracked in the future, our tokens have long expired.
const rsaKeyBits = 2048

// GenerateKeyPair generates a fresh RSA-2048 keypair and returns PEM-encoded
// public and private blocks. The private block uses the PKCS#1 RSA PRIVATE
// KEY form (matches the signing_keys column comment).
func GenerateKeyPair() (publicPEM, privatePEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
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

// signingKeyAAD binds signing-key blobs to their namespace so a wrapped
// private key cannot be swapped into another encrypted column (e.g. a user's
// TOTP secret). Static rather than per-kid because Insert generates the kid
// after WrapPrivateKey runs; cross-column swap is the load-bearing defense.
var signingKeyAAD = []byte("signing_key:private_pem")

// WrapPrivateKey AES-256-GCM-encrypts the private-key PEM with the operator's
// key-encryption key (SCHLASS_ENCRYPTION_KEY, 32 bytes).
func WrapPrivateKey(privatePEM, kek []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("oidc: kek must be 32 bytes, got %d", len(kek))
	}
	return crypto.Encrypt(privatePEM, kek, signingKeyAAD)
}

// UnwrapPrivateKey decrypts a wrapped private key.
func UnwrapPrivateKey(wrapped, kek []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("oidc: kek must be 32 bytes, got %d", len(kek))
	}
	return crypto.Decrypt(wrapped, kek, signingKeyAAD)
}

// ParsePrivatePEM parses a PEM-encoded RSA private key.
func ParsePrivatePEM(privatePEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privatePEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("oidc: invalid private PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ParsePublicPEM parses a PEM-encoded RSA public key.
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
