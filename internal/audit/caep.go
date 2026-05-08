// CAEP SET projection (REQ-AUD-051). Converts a stream.Event into an
// RFC 8417 Security Event Token claim map using the event_type → CAEP
// URN mapping from registry.go. Signing uses RS256 with typ=secevent+jwt
// per RFC 8417; the private key must be decrypted before calling SignCAEP.
package audit

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/abdo75/Schlass/internal/audit/stream"
)

// ProjectCAEP converts a stream.Event into an RFC 8417 SET claim map.
// ok=false means the event_type has no registered CAEP mapping and the
// caller should skip/filter the event. err is only non-nil for genuine
// projection failures (malformed data), not for unmapped types.
func ProjectCAEP(row stream.Event, issuer string) (claims map[string]any, urn string, ok bool, err error) {
	spec, found := Lookup(row.EventType)
	if !found || spec.OutboundCAEP == "" {
		return nil, "", false, nil
	}
	urn = spec.OutboundCAEP

	// sub_id: prefer actor_id; fall back to target_id when actor_id is absent
	// (e.g. system-initiated account.locked). "opaque" format per CAEP 1.0.
	subID := ""
	if row.ActorID != nil {
		subID = row.ActorID.String()
	} else if row.TargetID != nil {
		subID = *row.TargetID
	}

	eventPayload := map[string]any{
		"event_timestamp": row.EventTimestamp.Unix(),
	}
	enrichCAEPPayload(eventPayload, urn, row)

	claims = map[string]any{
		"iss": issuer,
		"iat": row.EventTimestamp.Unix(),
		"jti": row.ID.String(),
		"aud": []any{"urn:schlass:audit-stream"},
		"sub_id": map[string]any{
			"format": "opaque",
			"id":     subID,
		},
		"events": map[string]any{
			urn: eventPayload,
		},
	}
	return claims, urn, true, nil
}

// enrichCAEPPayload adds URN-specific claims to an already-created
// event payload map.
func enrichCAEPPayload(payload map[string]any, urn string, row stream.Event) {
	switch urn {
	case caepSessionRevoked:
		payload["initiating_entity"] = sessionInitiator(row)
		if row.ReasonCode != nil && *row.ReasonCode != "" {
			payload["reason_admin"] = *row.ReasonCode
		}

	case caepCredentialChange:
		payload["credential_type"] = credentialType(row.EventType)
		payload["change_type"] = credentialChangeType(row.EventType)

	case caepAccountDisabled:
		payload["reason"] = accountDisabledReason(row)

	case caepRiskLevelChange:
		// Only oidc.refresh.reuse_detected maps here; treat as fixed HIGH risk.
		payload["current_level"] = "HIGH"
		payload["previous_level"] = "LOW"
	}
}

func sessionInitiator(row stream.Event) string {
	// Derive from actor_type: a user actor is "user", an admin actor touching
	// another user's session is "admin", system actions are "policy".
	if row.ActorType == string(ActorTypeUser) {
		if row.TargetID != nil && row.ActorID != nil && *row.TargetID != row.ActorID.String() {
			return "admin"
		}
		return "user"
	}
	return "policy"
}

func credentialType(eventType string) string {
	if strings.Contains(eventType, "secret") {
		return "secret"
	}
	return "password"
}

func credentialChangeType(eventType string) string {
	switch {
	case strings.Contains(eventType, "reset") || strings.Contains(eventType, "password_reset"):
		return "revoke"
	case strings.Contains(eventType, "rotated"):
		return "update"
	default:
		return "update"
	}
}

func accountDisabledReason(row stream.Event) string {
	if row.ActorType == string(ActorTypeSystem) {
		return "policy"
	}
	if row.ActorID != nil && row.TargetID != nil && row.ActorID.String() == *row.TargetID {
		return "user-action"
	}
	return "admin-action"
}

// SignCAEP signs a CAEP claim map as an RFC 8417 SET (typ=secevent+jwt,
// alg=RS256). kid is the UUID string of the active signing key;
// privatePEM is the decrypted RSA private key PEM.
func SignCAEP(claims map[string]any, kid string, privatePEM []byte) (string, error) {
	block, _ := pem.Decode(privatePEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", fmt.Errorf("caep: invalid private PEM block")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("caep: parse private key: %w", err)
	}
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims(claims))
	tok.Header["kid"] = kid
	tok.Header["typ"] = "secevent+jwt"
	jws, err := tok.SignedString(priv)
	if err != nil {
		return "", fmt.Errorf("caep: sign SET: %w", err)
	}
	return jws, nil
}
