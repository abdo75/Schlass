//go:build integration

package integration

// Cross-endpoint return_to matrix — spec §7. Each test drives a complete
// login pipeline end-to-end and asserts the initial return_to surfaces
// verbatim in the terminal handler's redirect_to. Per-endpoint coverage
// lives in login_return_to_test.go and mfa_return_to_test.go; this file
// exists to prove the value survives the full pipeline, not just one hop.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

const wantReturnTo = "/authorize?client_id=abc&state=xyz&nonce=n1"

// assertRedirectTo decodes the JSON body and fails the test if its
// redirect_to field doesn't match want.
func assertRedirectTo(t *testing.T, body []byte, want string) {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode body: %v (raw=%s)", err, string(body))
	}
	if got := resp["redirect_to"]; got != want {
		t.Fatalf("redirect_to: got %v want %q (raw=%s)", got, want, string(body))
	}
}

// loginJSON drives POST /api/login and returns the recorder.
func loginJSON(t *testing.T, env *TestEnv, email, password, returnTo string) *httptest.ResponseRecorder {
	t.Helper()
	payload := map[string]string{"email": email, "password": password}
	if returnTo != "" {
		payload["return_to"] = returnTo
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

// cookieByName grabs a specific cookie from a response recorder.
func cookieByName(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestOIDCReturnTo_NoMFA_DirectRedirect — simplest happy path. Password-only
// login with return_to lands in one hop.
func TestOIDCReturnTo_NoMFA_DirectRedirect(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	if _, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	rec := loginJSON(t, env, "admin@example.com", "CorrectHorse1Battery", wantReturnTo)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	assertRedirectTo(t, rec.Body.Bytes(), wantReturnTo)
}

// TestOIDCReturnTo_MfaEnrollment_FullPipeline — login carries return_to into
// the enrollment Valkey hash; complete surfaces it as redirect_to.
func TestOIDCReturnTo_MfaEnrollment_FullPipeline(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

	// Login under mfa_required=true, not enrolled → 202 + enroll cookie.
	loginRec := loginJSON(t, env, "admin@example.com", "CorrectHorse1Battery", wantReturnTo)
	if loginRec.Code != http.StatusAccepted {
		t.Fatalf("login: want 202, got %d %s", loginRec.Code, loginRec.Body.String())
	}
	enrollCookie := cookieByName(loginRec, "schlass_mfa_enroll")
	if enrollCookie == nil {
		t.Fatal("no enroll cookie")
	}

	// Drive /start → /verify → /complete.
	startReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	startReq.AddCookie(enrollCookie)
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
	vReq.AddCookie(enrollCookie)
	env.Router.ServeHTTP(httptest.NewRecorder(), vReq)

	cBody, _ := json.Marshal(map[string]bool{"acknowledged": true})
	cReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/complete", bytes.NewReader(cBody))
	cReq.Header.Set("Content-Type", "application/json")
	cReq.AddCookie(enrollCookie)
	cRec := httptest.NewRecorder()
	env.Router.ServeHTTP(cRec, cReq)
	if cRec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", cRec.Code, cRec.Body.String())
	}
	assertRedirectTo(t, cRec.Body.Bytes(), wantReturnTo)
}

// TestOIDCReturnTo_MfaChallengeTOTP_FullPipeline — login carries return_to
// into the challenge Valkey hash; a successful TOTP surfaces it.
func TestOIDCReturnTo_MfaChallengeTOTP_FullPipeline(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	_, secret := enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")

	loginRec := loginJSON(t, env, "admin@example.com", "CorrectHorse1Battery", wantReturnTo)
	if loginRec.Code != http.StatusAccepted {
		t.Fatalf("login: %d %s", loginRec.Code, loginRec.Body.String())
	}
	challengeCookie := cookieByName(loginRec, "schlass_mfa_challenge")
	if challengeCookie == nil {
		t.Fatal("no challenge cookie")
	}

	code, _ := totp.GenerateCode(secret, time.Now())
	body, _ := json.Marshal(map[string]string{"code": code})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(challengeCookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", rec.Code, rec.Body.String())
	}
	assertRedirectTo(t, rec.Body.Bytes(), wantReturnTo)
}

// TestOIDCReturnTo_ForcePasswordChange_FullPipeline — admin creates user,
// user logs in with temp password + return_to, rotates password, lands on
// the deep link.
func TestOIDCReturnTo_ForcePasswordChange_FullPipeline(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

	if _, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	createBody, _ := json.Marshal(map[string]string{"email": "newuser@example.com", "role": "user"})
	createReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Origin", "http://localhost:3000")
	createReq.AddCookie(adminCookie)
	createRec := httptest.NewRecorder()
	env.Router.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create user: %d %s", createRec.Code, createRec.Body.String())
	}
	var createResp struct {
		TemporaryPassword string `json:"temporary_password"`
	}
	_ = json.NewDecoder(createRec.Body).Decode(&createResp)

	loginRec := loginJSON(t, env, "newuser@example.com", createResp.TemporaryPassword, wantReturnTo)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", loginRec.Code, loginRec.Body.String())
	}
	// Force-PW response does NOT echo redirect_to yet; it surfaces on
	// change-password success.
	var loginResp map[string]any
	_ = json.Unmarshal(loginRec.Body.Bytes(), &loginResp)
	if _, present := loginResp["redirect_to"]; present {
		t.Fatal("force-PW login must not emit redirect_to")
	}
	userSession := cookieByName(loginRec, "schlass_session")
	if userSession == nil {
		t.Fatal("no session cookie from force-PW login")
	}

	chBody, _ := json.Marshal(map[string]string{
		"current_password": createResp.TemporaryPassword,
		"new_password":     "RealPass4Now!",
	})
	chReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/change-password", bytes.NewReader(chBody))
	chReq.Header.Set("Content-Type", "application/json")
	chReq.AddCookie(userSession)
	chRec := httptest.NewRecorder()
	env.Router.ServeHTTP(chRec, chReq)
	if chRec.Code != http.StatusOK {
		t.Fatalf("change-password: %d %s", chRec.Code, chRec.Body.String())
	}
	assertRedirectTo(t, chRec.Body.Bytes(), wantReturnTo)
}

// TestOIDCReturnTo_ForcePasswordChange_Cleared — a second self-service
// change-password by the same user (no login in between) must NOT carry
// the old return_to, since the previous rotation destroyed the original
// session.
func TestOIDCReturnTo_ForcePasswordChange_Cleared(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	if _, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}
	adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")

	createBody, _ := json.Marshal(map[string]string{"email": "newuser@example.com", "role": "user"})
	createReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Origin", "http://localhost:3000")
	createReq.AddCookie(adminCookie)
	createRec := httptest.NewRecorder()
	env.Router.ServeHTTP(createRec, createReq)
	var createResp struct {
		TemporaryPassword string `json:"temporary_password"`
	}
	_ = json.NewDecoder(createRec.Body).Decode(&createResp)

	// First rotation — with return_to.
	loginRec := loginJSON(t, env, "newuser@example.com", createResp.TemporaryPassword, wantReturnTo)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("first login: %d", loginRec.Code)
	}
	session1 := cookieByName(loginRec, "schlass_session")

	chBody, _ := json.Marshal(map[string]string{
		"current_password": createResp.TemporaryPassword,
		"new_password":     "RealPass4Now!",
	})
	chReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/change-password", bytes.NewReader(chBody))
	chReq.Header.Set("Content-Type", "application/json")
	chReq.AddCookie(session1)
	chRec := httptest.NewRecorder()
	env.Router.ServeHTTP(chRec, chReq)
	if chRec.Code != http.StatusOK {
		t.Fatalf("first change-password: %d %s", chRec.Code, chRec.Body.String())
	}
	session2 := cookieByName(chRec, "schlass_session")
	if session2 == nil {
		t.Fatal("no rotated session from first change-password")
	}

	// Second rotation — same rotated session, no fresh login. Must emit
	// no redirect_to (the pending-return-to field on session2 is empty).
	chBody2, _ := json.Marshal(map[string]string{
		"current_password": "RealPass4Now!",
		"new_password":     "AnotherPass5Now!",
	})
	ch2Req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/change-password", bytes.NewReader(chBody2))
	ch2Req.Header.Set("Content-Type", "application/json")
	ch2Req.AddCookie(session2)
	ch2Rec := httptest.NewRecorder()
	env.Router.ServeHTTP(ch2Rec, ch2Req)
	if ch2Rec.Code != http.StatusOK {
		t.Fatalf("second change-password: %d %s", ch2Rec.Code, ch2Rec.Body.String())
	}
	var resp2 map[string]any
	_ = json.Unmarshal(ch2Rec.Body.Bytes(), &resp2)
	if _, present := resp2["redirect_to"]; present {
		t.Fatalf("return_to leaked across rotations: %v", resp2["redirect_to"])
	}
}

// TestOIDCReturnTo_OpenRedirect_Rejected_AtLoginEntry — assorted hostile
// return_to values never propagate through any stage of the pipeline.
func TestOIDCReturnTo_OpenRedirect_Rejected_AtLoginEntry(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	if _, err := env.Pool.Exec(t.Context(), `UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	hostile := []string{
		"https://evil.example.com/authorize",
		"//evil.example.com/authorize",
		"javascript:alert(1)",
		"/account",
		"/admin",
		"http://localhost:3000/authorize/../admin",
		"http://localhost:9999/authorize",
	}
	for _, bad := range hostile {
		t.Run(bad, func(t *testing.T) {
			rec := loginJSON(t, env, "admin@example.com", "CorrectHorse1Battery", bad)
			if rec.Code != http.StatusOK {
				t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
			}
			var resp map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			if _, present := resp["redirect_to"]; present {
				t.Fatalf("hostile return_to %q surfaced as redirect_to=%v", bad, resp["redirect_to"])
			}
		})
	}
}

// TestOIDCReturnTo_MfaEnrollment_OpenRedirect_NotStashed — hostile return_to
// at /api/login must not land in the mfa:enroll Valkey hash.
func TestOIDCReturnTo_MfaEnrollment_OpenRedirect_NotStashed(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

	rec := loginJSON(t, env, "admin@example.com", "CorrectHorse1Battery", "https://evil.example.com/authorize")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	enrollCookie := cookieByName(rec, "schlass_mfa_enroll")
	if enrollCookie == nil {
		t.Fatal("no enroll cookie")
	}
	// HGet return_to — expect redis.Nil (empty string).
	stored, err := env.ValkeyClient.HGet(t.Context(), "mfa:enroll:"+enrollCookie.Value, "return_to").Result()
	if err == nil && stored != "" {
		t.Fatalf("hostile return_to leaked into enroll hash: %q", stored)
	}
}

// TestOIDCReturnTo_NoReturnTo_EndToEnd — full MFA challenge flow without a
// return_to. Proves the absence is benign across the pipeline — no
// redirect_to anywhere.
func TestOIDCReturnTo_NoReturnTo_EndToEnd(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	_, secret := enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")

	loginRec := loginJSON(t, env, "admin@example.com", "CorrectHorse1Battery", "")
	if loginRec.Code != http.StatusAccepted {
		t.Fatalf("login: %d", loginRec.Code)
	}
	challengeCookie := cookieByName(loginRec, "schlass_mfa_challenge")

	code, _ := totp.GenerateCode(secret, time.Now())
	body, _ := json.Marshal(map[string]string{"code": code})
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(challengeCookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if _, present := resp["redirect_to"]; present {
		t.Fatalf("unexpected redirect_to without return_to: %v", resp["redirect_to"])
	}
}

// TestOIDCReturnTo_MfaChallenge_Recovery_FullPipeline — full login → recovery-
// code challenge → lands on deep link. Mirrors the TOTP pipeline test so
// both challenge branches are exercised end-to-end.
func TestOIDCReturnTo_MfaChallenge_Recovery_FullPipeline(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	uid := env.GetUserIDByEmail(t, "admin@example.com")

	// Drive enrollment manually to capture the recovery codes.
	enrollToken := "enroll-" + t.Name()
	enrollKey := "mfa:enroll:" + enrollToken
	env.Valkey.HSet(t.Context(), enrollKey, "user_id", uid.String())
	env.Valkey.Expire(t.Context(), enrollKey, 10*60)

	startReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	startReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: enrollToken})
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
	vReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: enrollToken})
	vRec := httptest.NewRecorder()
	env.Router.ServeHTTP(vRec, vReq)
	var vOut struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	_ = json.Unmarshal(vRec.Body.Bytes(), &vOut)
	if len(vOut.RecoveryCodes) == 0 {
		t.Fatalf("no recovery codes from verify")
	}

	cBody, _ := json.Marshal(map[string]bool{"acknowledged": true})
	cReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/complete", bytes.NewReader(cBody))
	cReq.Header.Set("Content-Type", "application/json")
	cReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: enrollToken})
	env.Router.ServeHTTP(httptest.NewRecorder(), cReq)

	// Login (enrolled now) with return_to.
	loginRec := loginJSON(t, env, "admin@example.com", "CorrectHorse1Battery", wantReturnTo)
	if loginRec.Code != http.StatusAccepted {
		t.Fatalf("login: %d %s", loginRec.Code, loginRec.Body.String())
	}
	challengeCookie := cookieByName(loginRec, "schlass_mfa_challenge")
	if challengeCookie == nil {
		t.Fatal("no challenge cookie")
	}

	rBody, _ := json.Marshal(map[string]string{"recovery_code": vOut.RecoveryCodes[0]})
	rReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(rBody))
	rReq.Header.Set("Content-Type", "application/json")
	rReq.AddCookie(challengeCookie)
	rRec := httptest.NewRecorder()
	env.Router.ServeHTTP(rRec, rReq)
	if rRec.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", rRec.Code, rRec.Body.String())
	}
	assertRedirectTo(t, rRec.Body.Bytes(), wantReturnTo)
}

