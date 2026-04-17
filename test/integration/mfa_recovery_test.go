package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// enrollAndCaptureRecoveryCodes enrolls the setup admin and returns (userID,
// secretBase32, plaintext recovery codes). Unlike enrollTestUser (which only
// returns userID + secret), this variant captures the codes emitted by
// /api/mfa/enrollment/verify for use in recovery-path challenge tests.
func enrollAndCaptureRecoveryCodes(t *testing.T, env *TestEnv, email, password string) (userID, secret string, codes []string) {
	t.Helper()
	env.CompleteSetup(t, email, password)
	uid := env.GetUserIDByEmail(t, email).String()
	token := "enrcap-" + t.Name()
	key := "mfa:enroll:" + token
	env.Valkey.HSet(t.Context(), key, "user_id", uid)
	env.Valkey.Expire(t.Context(), key, 10*60)

	startReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	startReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	sr := httptest.NewRecorder()
	env.Router.ServeHTTP(sr, startReq)
	var so struct{ SecretBase32 string `json:"secret_base32"` }
	_ = json.Unmarshal(sr.Body.Bytes(), &so)

	code, _ := totp.GenerateCode(so.SecretBase32, time.Now())
	vBody, _ := json.Marshal(map[string]string{"code": code})
	vReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/verify", bytes.NewReader(vBody))
	vReq.Header.Set("Content-Type", "application/json")
	vReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	vRec := httptest.NewRecorder()
	env.Router.ServeHTTP(vRec, vReq)
	var vo struct{ RecoveryCodes []string `json:"recovery_codes"` }
	_ = json.Unmarshal(vRec.Body.Bytes(), &vo)

	cBody, _ := json.Marshal(map[string]bool{"acknowledged": true})
	cReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/complete", bytes.NewReader(cBody))
	cReq.Header.Set("Content-Type", "application/json")
	cReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	env.Router.ServeHTTP(httptest.NewRecorder(), cReq)

	return uid, so.SecretBase32, vo.RecoveryCodes
}

func TestMfaChallenge_RecoveryCode_Happy(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	userID, _, codes := enrollAndCaptureRecoveryCodes(t, env, "admin@example.com", "CorrectHorse1Battery")
	if len(codes) != 10 {
		t.Fatalf("want 10 codes, got %d", len(codes))
	}

	tok := "rec-happy"
	key := "mfa:challenge:" + tok
	env.Valkey.HSet(t.Context(), key, "user_id", userID, "attempts_remaining", 5)
	env.Valkey.Expire(t.Context(), key, 120)

	body, _ := json.Marshal(map[string]string{"recovery_code": codes[0]})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "schlass_mfa_challenge", Value: tok})
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Count should drop to 9.
	uid := env.GetUserIDByEmail(t, "admin@example.com")
	n, _ := env.RecoveryCodeStore.CountUnused(t.Context(), env.Pool, uid)
	if n != 9 {
		t.Fatalf("want 9 unused codes remaining, got %d", n)
	}

	// Audit check — both login.succeeded and mfa.recovery_code_used should be present.
	var ev string
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT event_type FROM audit_logs WHERE event_type = 'mfa.recovery_code_used' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&ev); err != nil {
		t.Fatalf("mfa.recovery_code_used audit row missing: %v", err)
	}
	if ev != "mfa.recovery_code_used" {
		t.Fatal("mfa.recovery_code_used audit row missing")
	}
}

func TestMfaChallenge_RecoveryCode_ReusedRejected(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	userID, _, codes := enrollAndCaptureRecoveryCodes(t, env, "admin@example.com", "CorrectHorse1Battery")

	// Burn code 0 once.
	tok1 := "rec-burn-1"
	key1 := "mfa:challenge:" + tok1
	env.Valkey.HSet(t.Context(), key1, "user_id", userID, "attempts_remaining", 5)
	env.Valkey.Expire(t.Context(), key1, 120)
	body, _ := json.Marshal(map[string]string{"recovery_code": codes[0]})
	r1 := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(body))
	r1.Header.Set("Content-Type", "application/json")
	r1.AddCookie(&http.Cookie{Name: "schlass_mfa_challenge", Value: tok1})
	env.Router.ServeHTTP(httptest.NewRecorder(), r1)

	// Try to reuse — must reject.
	tok2 := "rec-burn-2"
	key2 := "mfa:challenge:" + tok2
	env.Valkey.HSet(t.Context(), key2, "user_id", userID, "attempts_remaining", 5)
	env.Valkey.Expire(t.Context(), key2, 120)
	r2 := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(body))
	r2.Header.Set("Content-Type", "application/json")
	r2.AddCookie(&http.Cookie{Name: "schlass_mfa_challenge", Value: tok2})
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, r2)
	if rec.Code == http.StatusOK {
		t.Fatal("reusing a burned recovery code should be rejected")
	}
}

func TestMfaChallenge_RecoveryCode_InvalidCode(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	userID, _, _ := enrollAndCaptureRecoveryCodes(t, env, "admin@example.com", "CorrectHorse1Battery")

	tok := "rec-invalid"
	key := "mfa:challenge:" + tok
	env.Valkey.HSet(t.Context(), key, "user_id", userID, "attempts_remaining", 5)
	env.Valkey.Expire(t.Context(), key, 120)

	body, _ := json.Marshal(map[string]string{"recovery_code": "ZZZZ-ZZZZ"})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "schlass_mfa_challenge", Value: tok})
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}
