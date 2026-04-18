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

func TestMfaEnrollmentComplete_Happy(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	userID := env.GetUserIDByEmail(t, "admin@example.com")

	token := "complete-happy-token"
	key := "mfa:enroll:" + token
	env.Valkey.HSet(t.Context(), key, "user_id", userID.String())
	env.Valkey.Expire(t.Context(), key, 10*60)

	// /start
	startReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	startReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	startRec := httptest.NewRecorder()
	env.Router.ServeHTTP(startRec, startReq)
	var startOut struct{ SecretBase32 string `json:"secret_base32"` }
	_ = json.Unmarshal(startRec.Body.Bytes(), &startOut)

	// /verify
	code, _ := totp.GenerateCode(startOut.SecretBase32, time.Now())
	vBody, _ := json.Marshal(map[string]string{"code": code})
	vReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/verify", bytes.NewReader(vBody))
	vReq.Header.Set("Content-Type", "application/json")
	vReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	vRec := httptest.NewRecorder()
	env.Router.ServeHTTP(vRec, vReq)
	if vRec.Code != http.StatusOK {
		t.Fatalf("verify: want 200, got %d", vRec.Code)
	}

	// /complete
	cBody, _ := json.Marshal(map[string]bool{"acknowledged": true})
	cReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/complete", bytes.NewReader(cBody))
	cReq.Header.Set("Content-Type", "application/json")
	cReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	cRec := httptest.NewRecorder()
	env.Router.ServeHTTP(cRec, cReq)
	if cRec.Code != http.StatusOK {
		t.Fatalf("complete: want 200, got %d: %s", cRec.Code, cRec.Body.String())
	}

	// Session cookie must be set.
	var sessionCookie *http.Cookie
	for _, c := range cRec.Result().Cookies() {
		if c.Name == "schlass_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("no schlass_session cookie set after /complete")
	}

	// DB: totp_enrolled_at non-null, 10 recovery codes inserted.
	user, err := env.UserStore.GetByID(t.Context(), env.Pool, userID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if user.TOTPEnrolledAt == nil {
		t.Fatal("totp_enrolled_at still null after /complete")
	}
	if len(user.TOTPSecretEncrypted) == 0 {
		t.Fatal("totp_secret_encrypted empty after /complete")
	}
	count, err := env.RecoveryCodeStore.CountUnused(t.Context(), env.Pool, userID)
	if err != nil {
		t.Fatalf("CountUnused: %v", err)
	}
	if count != 10 {
		t.Fatalf("want 10 unused recovery codes, got %d", count)
	}

	// Audit: mfa.enrollment_completed row present.
	var ev string
	err = env.Pool.QueryRow(t.Context(),
		`SELECT event_type FROM audit_logs WHERE event_type = 'mfa.enrollment_completed' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&ev)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}

	// Valkey token must be deleted.
	exists, _ := env.Valkey.Exists(t.Context(), key).Result()
	if exists != 0 {
		t.Fatal("enrollment token should be deleted after /complete")
	}
}

func TestMfaEnrollmentComplete_NotAcknowledged_400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	userID := env.GetUserIDByEmail(t, "admin@example.com")

	token := "complete-ack-token"
	key := "mfa:enroll:" + token
	env.Valkey.HSet(t.Context(), key, "user_id", userID.String())
	env.Valkey.Expire(t.Context(), key, 10*60)

	// start + verify to get to the final state
	startReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	startReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	startRec := httptest.NewRecorder()
	env.Router.ServeHTTP(startRec, startReq)
	var startOut struct{ SecretBase32 string `json:"secret_base32"` }
	_ = json.Unmarshal(startRec.Body.Bytes(), &startOut)

	code, _ := totp.GenerateCode(startOut.SecretBase32, time.Now())
	vBody, _ := json.Marshal(map[string]string{"code": code})
	vReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/verify", bytes.NewReader(vBody))
	vReq.Header.Set("Content-Type", "application/json")
	vReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	env.Router.ServeHTTP(httptest.NewRecorder(), vReq)

	// /complete with acknowledged=false
	cBody, _ := json.Marshal(map[string]bool{"acknowledged": false})
	cReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/complete", bytes.NewReader(cBody))
	cReq.Header.Set("Content-Type", "application/json")
	cReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	cRec := httptest.NewRecorder()
	env.Router.ServeHTTP(cRec, cReq)
	if cRec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 when acknowledged=false, got %d", cRec.Code)
	}

	// User should NOT be enrolled.
	u, _ := env.UserStore.GetByID(t.Context(), env.Pool, userID)
	if u.TOTPEnrolledAt != nil {
		t.Fatal("user should not be enrolled after failed /complete")
	}
}

func TestMfaEnrollmentStart_ProvisionURI_UsesInstanceName(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	userID := env.GetUserIDByEmail(t, "admin@example.com")

	// Overwrite the instance_name set by CompleteSetup. Values are stored as
	// JSON so we supply a JSON-encoded string literal.
	if _, err := env.Pool.Exec(t.Context(),
		`UPDATE instance_config SET value = '"ACME Corp"' WHERE key = 'instance_name'`,
	); err != nil {
		t.Fatalf("set instance_name: %v", err)
	}

	token := "test-issuer-token"
	key := "mfa:enroll:" + token
	env.Valkey.HSet(t.Context(), key, "user_id", userID.String())
	env.Valkey.Expire(t.Context(), key, 10*60)

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	req.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var out struct {
		ProvisionURI string `json:"provision_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// The provision URI must encode "ACME Corp" as the issuer, not the URL host.
	if !strings.Contains(out.ProvisionURI, "issuer=ACME+Corp") &&
		!strings.Contains(out.ProvisionURI, "issuer=ACME%20Corp") {
		t.Fatalf("provision_uri should contain issuer=ACME Corp (url-encoded); got %s", out.ProvisionURI)
	}
}

func TestMfaEnrollmentStart_ProvisionURI_FallsBackToSchlass(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	userID := env.GetUserIDByEmail(t, "admin@example.com")

	// Blank the instance_name so GetInstanceName returns "". Values are stored
	// as JSON so an empty string is the JSON literal '""'.
	if _, err := env.Pool.Exec(t.Context(),
		`UPDATE instance_config SET value = '""' WHERE key = 'instance_name'`,
	); err != nil {
		t.Fatalf("blank instance_name: %v", err)
	}

	token := "test-fallback-token"
	key := "mfa:enroll:" + token
	env.Valkey.HSet(t.Context(), key, "user_id", userID.String())
	env.Valkey.Expire(t.Context(), key, 10*60)

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	req.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var out struct {
		ProvisionURI string `json:"provision_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !strings.Contains(out.ProvisionURI, "issuer=Schlass") {
		t.Fatalf("expected fallback issuer=Schlass in provision_uri; got %s", out.ProvisionURI)
	}
}

// extractCookie finds a named cookie in an httptest.ResponseRecorder's result.
// Fails the test if the cookie is not present or has an empty value.
func extractCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	t.Fatalf("cookie %q not found in response", name)
	return nil
}

func TestMfaEnrollmentStart_SessionAuthed_MintsCookieAndProceeds(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	userID := env.GetUserIDByEmail(t, "admin@example.com")

	// Admin ends up holding a valid session after setup. Simulate that.
	sessionCookie := env.DirectCreateSession(t, userID)

	// Hit /start with ONLY a session cookie (no enrollment cookie).
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Response should include secret+uri (same as cookie-authed path).
	var out struct {
		SecretBase32 string `json:"secret_base32"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.SecretBase32 == "" {
		t.Fatal("empty secret")
	}

	// A fresh schlass_mfa_enroll cookie should be set.
	enrollCookie := extractCookie(t, rec, "schlass_mfa_enroll")
	if enrollCookie == nil || enrollCookie.Value == "" {
		t.Fatal("expected schlass_mfa_enroll cookie to be set for session-authed /start")
	}
}

func TestMfaEnrollmentComplete_SessionAuthed_DoesNotRotateSession(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
	userID := env.GetUserIDByEmail(t, "admin@example.com")
	sessionCookie := env.DirectCreateSession(t, userID)

	// /start — session-authed.
	startReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	startReq.AddCookie(sessionCookie)
	startRec := httptest.NewRecorder()
	env.Router.ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("start: want 200, got %d: %s", startRec.Code, startRec.Body.String())
	}
	var startOut struct {
		SecretBase32 string `json:"secret_base32"`
	}
	_ = json.Unmarshal(startRec.Body.Bytes(), &startOut)
	enrollCookie := extractCookie(t, startRec, "schlass_mfa_enroll")

	// /verify
	code, _ := totp.GenerateCode(startOut.SecretBase32, time.Now())
	vBody, _ := json.Marshal(map[string]string{"code": code})
	vReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/verify", bytes.NewReader(vBody))
	vReq.Header.Set("Content-Type", "application/json")
	vReq.AddCookie(sessionCookie)
	vReq.AddCookie(enrollCookie)
	vRec := httptest.NewRecorder()
	env.Router.ServeHTTP(vRec, vReq)
	if vRec.Code != http.StatusOK {
		t.Fatalf("verify: want 200, got %d: %s", vRec.Code, vRec.Body.String())
	}

	// /complete
	cBody, _ := json.Marshal(map[string]bool{"acknowledged": true})
	cReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/complete", bytes.NewReader(cBody))
	cReq.Header.Set("Content-Type", "application/json")
	cReq.AddCookie(sessionCookie)
	cReq.AddCookie(enrollCookie)
	cRec := httptest.NewRecorder()
	env.Router.ServeHTTP(cRec, cReq)
	if cRec.Code != http.StatusOK {
		t.Fatalf("complete: want 200, got %d: %s", cRec.Code, cRec.Body.String())
	}

	// No NEW session cookie should be issued (the existing one is still valid).
	for _, c := range cRec.Result().Cookies() {
		if c.Name == "schlass_session" && c.Value != "" && c.MaxAge >= 0 {
			t.Fatal("session-authed /complete should not issue a new session cookie")
		}
	}

	// Enrollment cookie should be cleared.
	var enrollCleared bool
	for _, c := range cRec.Result().Cookies() {
		if c.Name == "schlass_mfa_enroll" && c.MaxAge < 0 {
			enrollCleared = true
		}
	}
	if !enrollCleared {
		t.Fatal("session-authed /complete should clear the enrollment cookie")
	}

	// DB committed — totp_enrolled_at non-null.
	user, err := env.UserStore.GetByID(t.Context(), env.Pool, userID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if user.TOTPEnrolledAt == nil {
		t.Fatal("totp_enrolled_at still null after session-authed /complete")
	}
}

func TestMfaEnrollmentStart_AlreadyEnrolled_SessionAuthed_Returns400(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	// Fully enroll the admin (uses enrollment cookie path internally).
	enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")
	userID := env.GetUserIDByEmail(t, "admin@example.com")
	sessionCookie := env.DirectCreateSession(t, userID)

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 MFA_ALREADY_ENROLLED, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "MFA_ALREADY_ENROLLED" {
		t.Fatalf("want error=MFA_ALREADY_ENROLLED, got %v", body["error"])
	}
}
