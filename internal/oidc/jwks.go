package oidc

import (
	"encoding/base64"
	"math/big"
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

// PublicPEMToJWK converts one RSA public key PEM + kid to a JWK entry.
// Caller owns JWK set assembly (see signingkeys.BuildJWKSet).
func PublicPEMToJWK(kid string, publicPEM []byte) (JWK, error) {
	pub, err := ParsePublicPEM(publicPEM)
	if err != nil {
		return JWK{}, err
	}
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   b64url(pub.N),
		E:   b64url(big.NewInt(int64(pub.E))),
	}, nil
}

func b64url(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}
