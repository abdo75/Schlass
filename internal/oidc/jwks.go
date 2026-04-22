package oidc

import (
	"encoding/base64"
	"math/big"

	"github.com/abdo75/Schlass/internal/store"
)

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// BuildJWKSet converts publishable signing keys (active + retiring) to JWKS.
// JWT kid header must match the JWK kid so verifiers pick the right key.
func BuildJWKSet(keys []*store.SigningKey) (JWKSet, error) {
	out := JWKSet{Keys: make([]JWK, 0, len(keys))}
	for _, k := range keys {
		pub, err := ParsePublicPEM(k.PublicKeyPEM)
		if err != nil {
			return JWKSet{}, err
		}
		out.Keys = append(out.Keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: k.ID.String(),
			N:   b64url(pub.N),
			E:   b64url(big.NewInt(int64(pub.E))),
		})
	}
	return out, nil
}

func b64url(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}
