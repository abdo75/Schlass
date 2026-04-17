package crypto_test

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/abdo75/Schlass/internal/crypto"
)

func TestGenerateTOTPSecret(t *testing.T) {
	s1, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if len(s1) < 26 {
		t.Fatalf("secret shorter than expected (want ≥26 base32 chars for 160 bits): got %d", len(s1))
	}
	// Base32 alphabet: A-Z, 2-7 (padding stripped by the helper).
	for _, r := range s1 {
		if (r < 'A' || r > 'Z') && (r < '2' || r > '7') {
			t.Fatalf("non-base32 char %q in secret", r)
		}
	}

	s2, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("second GenerateTOTPSecret: %v", err)
	}
	if s1 == s2 {
		t.Fatal("two consecutive secrets were identical — crypto/rand is not doing its job")
	}
}

func TestValidateTOTP_CurrentStep(t *testing.T) {
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	matched, step, err := crypto.ValidateTOTP(code, secret, 0)
	if err != nil {
		t.Fatalf("ValidateTOTP: %v", err)
	}
	if !matched {
		t.Fatal("current-step code should validate")
	}
	expectedStep := time.Now().Unix() / 30
	if step != expectedStep && step != expectedStep-1 && step != expectedStep+1 {
		t.Fatalf("matched step %d not within ±1 of current %d", step, expectedStep)
	}
}

func TestValidateTOTP_PreviousStep_Allowed(t *testing.T) {
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	previous := time.Now().Add(-30 * time.Second)
	code, err := totp.GenerateCode(secret, previous)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	matched, _, err := crypto.ValidateTOTP(code, secret, 0)
	if err != nil {
		t.Fatalf("ValidateTOTP: %v", err)
	}
	if !matched {
		t.Fatal("code from -30s should validate with Skew: 1")
	}
}

func TestValidateTOTP_TwoStepsBack_Rejected(t *testing.T) {
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	tooOld := time.Now().Add(-75 * time.Second)
	code, err := totp.GenerateCode(secret, tooOld)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	matched, _, err := crypto.ValidateTOTP(code, secret, 0)
	if err != nil {
		t.Fatalf("ValidateTOTP: %v", err)
	}
	if matched {
		t.Fatal("code from -75s should NOT validate with Skew: 1")
	}
}

func TestValidateTOTP_ReplayRejected(t *testing.T) {
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	// First validate — should match and return step.
	matched, step, err := crypto.ValidateTOTP(code, secret, 0)
	if err != nil {
		t.Fatalf("first ValidateTOTP: %v", err)
	}
	if !matched {
		t.Fatal("first validate should match")
	}

	// Second validate with lastCounter = step — replay, must reject.
	matched2, _, err := crypto.ValidateTOTP(code, secret, step)
	if err != nil {
		t.Fatalf("second ValidateTOTP: %v", err)
	}
	if matched2 {
		t.Fatal("replay of same code should reject when lastCounter >= step")
	}
}

func TestValidateTOTP_BadCode(t *testing.T) {
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	matched, _, err := crypto.ValidateTOTP("000000", secret, 0)
	if err != nil {
		t.Fatalf("ValidateTOTP: %v", err)
	}
	if matched {
		t.Fatal("zero code should (almost certainly) not validate against a random secret")
	}
}

func TestBuildProvisionURI(t *testing.T) {
	uri, err := crypto.BuildProvisionURI("Schlass", "alice@example.com", "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("BuildProvisionURI: %v", err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/Schlass:alice@example.com") {
		t.Fatalf("URI missing expected prefix: %s", uri)
	}
	if !strings.Contains(uri, "secret=JBSWY3DPEHPK3PXP") {
		t.Fatal("URI missing secret param")
	}
	if !strings.Contains(uri, "issuer=Schlass") {
		t.Fatal("URI missing issuer param")
	}
}
