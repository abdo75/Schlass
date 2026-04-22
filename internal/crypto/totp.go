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

const totpSecretBytes = 20

var totpAlgorithmSHA1 = otp.AlgorithmSHA1

func GenerateTOTPSecret() (string, error) {
	b := make([]byte, totpSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func ValidateTOTP(code, secret string, lastCounter int64) (matched bool, matchedStep int64, err error) {
	now := time.Now()
	currentStep := now.Unix() / 30

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

func BuildProvisionURI(issuer, accountEmail, secretBase32 string) (string, error) {
	if issuer == "" || accountEmail == "" || secretBase32 == "" {
		return "", fmt.Errorf("build provision uri: empty field")
	}

	label := url.PathEscape(issuer + ":" + accountEmail)
	q := url.Values{}
	q.Set("secret", secretBase32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode(), nil
}
