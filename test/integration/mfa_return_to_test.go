//go:build integration

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

// TestMfaChallenge_TOTP_ReturnTo_EmitsRedirectTo proves that a return_to
// stashed in the mfa:challenge Valkey hash (by PostLogin at M6.2) surfaces
// as redirect_to on the successful-challenge 200.
func TestMfaChallenge_TOTP_ReturnTo_EmitsRedirectTo(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	userID, secret := enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")

	challengeToken := "challenge-" + t.Name()
	key := "mfa:challenge:" + challengeToken
	want := "/authorize?client_id=abc&state=xyz"
	env.Valkey.HSet(t.Context(), key,
		"user_id", userID,
		"attempts_remaining", 5,
		"return_to", want,
	)
	env.Valkey.Expire(t.Context(), key, 120)

	code, _ := totp.GenerateCode(secret, time.Now())
	body, _ := json.Marshal(map[string]string{"code": code})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "schlass_mfa_challenge", Value: challengeToken})
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if got := resp["redirect_to"]; got != want {
		t.Fatalf("redirect_to: got %v want %q", got, want)
	}
}

// TestMfaChallenge_TOTP_NoReturnTo_OmitsRedirectTo confirms the field is
// absent (not echoed as empty string) when no return_to was stashed.
func TestMfaChallenge_TOTP_NoReturnTo_OmitsRedirectTo(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	userID, secret := enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")

	challengeToken := "challenge-" + t.Name()
	key := "mfa:challenge:" + challengeToken
	env.Valkey.HSet(t.Context(), key, "user_id", userID, "attempts_remaining", 5)
	env.Valkey.Expire(t.Context(), key, 120)

	code, _ := totp.GenerateCode(secret, time.Now())
	body, _ := json.Marshal(map[string]string{"code": code})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "schlass_mfa_challenge", Value: challengeToken})
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if _, present := resp["redirect_to"]; present {
		t.Fatalf("unexpected redirect_to in response: %v", resp["redirect_to"])
	}
}

// TestMfaChallenge_Recovery_ReturnTo_EmitsRedirectTo exercises the recovery-
// code branch of the challenge dispatch.
func TestMfaChallenge_Recovery_ReturnTo_EmitsRedirectTo(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()

	// Enroll + seed recovery codes via the normal enrollment flow, then pull
	// the plaintext codes out of the /verify response.
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	uid := env.GetUserIDByEmail(t, "admin@example.com")

	token := "enroll-" + t.Name()
	enrollKey := "mfa:enroll:" + token
	env.Valkey.HSet(t.Context(), enrollKey, "user_id", uid.String())
	env.Valkey.Expire(t.Context(), enrollKey, 10*60)

	startReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	startReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	startRec := httptest.NewRecorder()
	env.Router.ServeHTTP(startRec, startReq)
	var startOut struct {
		SecretBase32 string `json:"secret_base32"`
	}
	_ = json.Unmarshal(startRec.Body.Bytes(), &startOut)

	code, _ := totp.GenerateCode(startOut.SecretBase32, time.Now())
	vBody, _ := json.Marshal(map[string]string{"code": code})
	vReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/verify", bytes.NewReader(vBody))
	vReq.Header.Set("Content-Type", "application/json")
	vReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	vRec := httptest.NewRecorder()
	env.Router.ServeHTTP(vRec, vReq)
	var vOut struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(vRec.Body.Bytes(), &vOut); err != nil || len(vOut.RecoveryCodes) == 0 {
		t.Fatalf("enrollment verify failed: %v %s", err, vRec.Body.String())
	}

	cBody, _ := json.Marshal(map[string]bool{"acknowledged": true})
	cReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/complete", bytes.NewReader(cBody))
	cReq.Header.Set("Content-Type", "application/json")
	cReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	env.Router.ServeHTTP(httptest.NewRecorder(), cReq)

	// Drive the challenge with the first recovery code and a stashed return_to.
	challengeToken := "challenge-" + t.Name()
	challengeKey := "mfa:challenge:" + challengeToken
	want := "/authorize?client_id=abc&state=xyz"
	env.Valkey.HSet(t.Context(), challengeKey,
		"user_id", uid.String(),
		"attempts_remaining", 5,
		"return_to", want,
	)
	env.Valkey.Expire(t.Context(), challengeKey, 120)

	rBody, _ := json.Marshal(map[string]string{"recovery_code": vOut.RecoveryCodes[0]})
	rReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(rBody))
	rReq.Header.Set("Content-Type", "application/json")
	rReq.AddCookie(&http.Cookie{Name: "schlass_mfa_challenge", Value: challengeToken})
	rRec := httptest.NewRecorder()
	env.Router.ServeHTTP(rRec, rReq)
	if rRec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rRec.Code, rRec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rRec.Body.Bytes(), &resp)
	if got := resp["redirect_to"]; got != want {
		t.Fatalf("redirect_to: got %v want %q", got, want)
	}
}
