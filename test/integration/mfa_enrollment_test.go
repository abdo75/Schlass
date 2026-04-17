package integration

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// Seeds a schlass_mfa_enroll token into Valkey directly (bypassing /api/login
// which does not yet emit 202 — that's Task 12) and verifies /start returns
// a fresh secret + provision URI and writes the secret back into the same
// Valkey key.
func TestMfaEnrollmentStart_Isolated(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

	userID := env.GetUserIDByEmail(t, "admin@example.com")

	token := "test-enroll-token-abc"
	key := "mfa:enroll:" + token
	if err := env.Valkey.HSet(t.Context(), key, "user_id", userID.String()).Err(); err != nil {
		t.Fatalf("HSet user_id: %v", err)
	}
	if err := env.Valkey.Expire(t.Context(), key, 10*60).Err(); err != nil {
		t.Fatalf("Expire: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	req.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var out struct {
		SecretBase32 string `json:"secret_base32"`
		ProvisionURI string `json:"provision_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.SecretBase32 == "" {
		t.Fatal("empty secret_base32")
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(out.SecretBase32); err != nil {
		t.Fatalf("secret_base32 not valid base32 (unpadded): %v", err)
	}
	if !strings.HasPrefix(out.ProvisionURI, "otpauth://totp/") {
		t.Fatalf("provision_uri missing otpauth prefix: %s", out.ProvisionURI)
	}
	if !strings.Contains(out.ProvisionURI, "secret="+out.SecretBase32) {
		t.Fatal("provision_uri secret doesn't match returned secret_base32")
	}

	stored, err := env.Valkey.HGet(t.Context(), key, "secret_base32").Result()
	if err != nil {
		t.Fatalf("HGet secret_base32: %v", err)
	}
	if stored != out.SecretBase32 {
		t.Fatalf("Valkey secret %q != response secret %q", stored, out.SecretBase32)
	}
}

func TestMfaEnrollmentStart_NoCookie_401(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestMfaEnrollmentStart_AlreadyEnrolled_400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	uid := env.GetUserIDByEmail(t, "admin@example.com")

	// Simulate already-enrolled: set totp_enrolled_at on the user.
	if _, err := env.Pool.Exec(t.Context(),
		`UPDATE users SET totp_enrolled_at = now(), totp_secret_encrypted = '\x00'::bytea WHERE id = $1`,
		uid,
	); err != nil {
		t.Fatalf("seed enrolled: %v", err)
	}

	token := "already-enrolled-token"
	env.Valkey.HSet(t.Context(), "mfa:enroll:"+token, "user_id", uid.String())
	env.Valkey.Expire(t.Context(), "mfa:enroll:"+token, 10*60)

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	req.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "MFA_ALREADY_ENROLLED" {
		t.Fatalf("want error=MFA_ALREADY_ENROLLED, got %v", body["error"])
	}
}

func TestMfaEnrollmentVerify_ValidCode_ReturnsRecoveryCodes(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	userID := env.GetUserIDByEmail(t, "admin@example.com")

	token := "verify-happy-token"
	key := "mfa:enroll:" + token
	env.Valkey.HSet(t.Context(), key, "user_id", userID.String())
	env.Valkey.Expire(t.Context(), key, 10*60)

	startReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	startReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	startRec := httptest.NewRecorder()
	env.Router.ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("start: want 200, got %d: %s", startRec.Code, startRec.Body.String())
	}
	var startOut struct {
		SecretBase32 string `json:"secret_base32"`
	}
	_ = json.Unmarshal(startRec.Body.Bytes(), &startOut)

	code, err := totp.GenerateCode(startOut.SecretBase32, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	vBody, _ := json.Marshal(map[string]string{"code": code})
	vReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/verify", bytes.NewReader(vBody))
	vReq.Header.Set("Content-Type", "application/json")
	vReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	vRec := httptest.NewRecorder()
	env.Router.ServeHTTP(vRec, vReq)
	if vRec.Code != http.StatusOK {
		t.Fatalf("verify: want 200, got %d: %s", vRec.Code, vRec.Body.String())
	}

	var vOut struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	_ = json.Unmarshal(vRec.Body.Bytes(), &vOut)
	if len(vOut.RecoveryCodes) != 10 {
		t.Fatalf("want 10 recovery codes, got %d", len(vOut.RecoveryCodes))
	}

	// Valkey should now have the recovery_hashes field populated.
	stored, err := env.Valkey.HGet(t.Context(), key, "recovery_hashes").Result()
	if err != nil {
		t.Fatalf("HGet recovery_hashes: %v", err)
	}
	if stored == "" {
		t.Fatal("recovery_hashes empty in Valkey after verify")
	}
}

func TestMfaEnrollmentVerify_InvalidCode_FiveStrikes_Invalidates(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	userID := env.GetUserIDByEmail(t, "admin@example.com")

	token := "verify-max-token"
	key := "mfa:enroll:" + token
	env.Valkey.HSet(t.Context(), key, "user_id", userID.String())
	env.Valkey.Expire(t.Context(), key, 10*60)

	// /start sets the secret so the verify path has something to check against.
	startReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	startReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	env.Router.ServeHTTP(httptest.NewRecorder(), startReq)

	badBody, _ := json.Marshal(map[string]string{"code": "000000"})
	for i := 0; i < 5; i++ {
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/verify", bytes.NewReader(badBody))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	// 6th attempt — token should be invalidated.
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/verify", bytes.NewReader(badBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("6th attempt: want 401, got %d", rec.Code)
	}
	// Valkey key should be gone.
	exists, _ := env.Valkey.Exists(t.Context(), key).Result()
	if exists != 0 {
		t.Fatal("enroll token key should be deleted after max attempts")
	}
}
