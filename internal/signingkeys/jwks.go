package signingkeys

import "github.com/abdo75/Schlass/internal/oidc"

// BuildJWKSet converts publishable signing keys (active + retiring) to JWKS.
// JWT kid header must match the JWK kid so verifiers pick the right key.
func BuildJWKSet(keys []*SigningKey) (oidc.JWKSet, error) {
	out := oidc.JWKSet{Keys: make([]oidc.JWK, 0, len(keys))}
	for _, k := range keys {
		jwk, err := oidc.PublicPEMToJWK(k.ID.String(), k.PublicKeyPEM)
		if err != nil {
			return oidc.JWKSet{}, err
		}
		out.Keys = append(out.Keys, jwk)
	}
	return out, nil
}
