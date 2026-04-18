package crypto

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// totpSecretBytes produces 160-bit secrets as recommended by RFC 6238 (and
// what pquerna/otp's Generate() emits by default). 20 random bytes base32-
// encodes to 32 chars (with padding) or 26 chars (unpadded) — pquerna/otp
// strips padding, so we emit unpadded here too for consistency.
const totpSecretBytes = 20

// totpAlgorithmSHA1 is the standard RFC 6238 algorithm. Named in a var so
// the ValidateOpts literal reads cleanly and there's a single swap-point if
// we ever move off SHA1.
var totpAlgorithmSHA1 = otp.AlgorithmSHA1

// GenerateTOTPSecret returns a fresh base32-encoded (unpadded, uppercase)
// TOTP secret suitable for a `otpauth://totp/...?secret=...` provision URI.
// 160 bits of entropy from crypto/rand.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, totpSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// ValidateTOTP checks `code` against `secret` with Skew=1 (accepts ±1 step =
// ±30s drift) and replay prevention: the matched step must be strictly
// greater than `lastCounter`. Returns (matched, matchedStep, error).
//
// On match, matchedStep is the TOTP step index (unix/30) that validated; the
// caller MUST persist this as the new lastCounter before issuing the session
// so the same code cannot validate twice. On non-match, matchedStep is 0 and
// should be ignored.
//
// pquerna/otp's totp.Validate does not surface which step matched, so we
// loop manually over the skew window (current step, -1, +1) and call
// totp.ValidateCustom with Skew=0 for each.
func ValidateTOTP(code, secret string, lastCounter int64) (matched bool, matchedStep int64, err error) {
	now := time.Now()
	currentStep := now.Unix() / 30
	// Iterate in the order skew=0, -1, +1. Earliest match wins, but we still
	// enforce the lastCounter gate — an older step within skew cannot be a
	// valid match if it's already ≤ lastCounter.
	for _, offset := range []int64{0, -1, 1} {
		step := currentStep + offset
		if step <= lastCounter {
			continue
		}
		stepTime := time.Unix(step*30, 0)
		ok, verr := totp.ValidateCustom(code, secret, stepTime, totp.ValidateOpts{
			Period:    30,
			Skew:      0,
			Digits:    6,
			Algorithm: totpAlgorithmSHA1,
		})
		if verr != nil {
			return false, 0, fmt.Errorf("validate totp: %w", verr)
		}
		if ok {
			return true, step, nil
		}
	}
	return false, 0, nil
}

// BuildProvisionURI assembles the otpauth:// URI that the QR code encodes.
// Format per https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
func BuildProvisionURI(issuer, accountEmail, secretBase32 string) (string, error) {
	if issuer == "" || accountEmail == "" || secretBase32 == "" {
		return "", fmt.Errorf("build provision uri: empty field")
	}
	// Label is "<issuer>:<account>" URL-encoded. The issuer param is also set
	// (redundant but standard — some authenticators honor one or the other).
	label := url.PathEscape(issuer + ":" + accountEmail)
	q := url.Values{}
	q.Set("secret", secretBase32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode(), nil
}
