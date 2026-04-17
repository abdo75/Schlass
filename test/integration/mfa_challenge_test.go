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

// enrollTestUser enrolls the setup admin and returns (userID, secretBase32).
// Used by challenge tests to get a user with a live TOTP secret.
func enrollTestUser(t *testing.T, env *TestEnv, email, password string) (userID string, secret string) {
	t.Helper()
	env.CompleteSetup(t, email, password)
	uid := env.GetUserIDByEmail(t, email)

	token := "enroll-" + t.Name()
	key := "mfa:enroll:" + token
	env.Valkey.HSet(t.Context(), key, "user_id", uid.String())
	env.Valkey.Expire(t.Context(), key, 10*60)

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
	env.Router.ServeHTTP(httptest.NewRecorder(), vReq)

	cBody, _ := json.Marshal(map[string]bool{"acknowledged": true})
	cReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/complete", bytes.NewReader(cBody))
	cReq.Header.Set("Content-Type", "application/json")
	cReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
	env.Router.ServeHTTP(httptest.NewRecorder(), cReq)

	return uid.String(), startOut.SecretBase32
}

func TestMfaChallenge_TOTP_Happy(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	userID, secret := enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")

	// Seed challenge token in Valkey (simulating what PostLogin will do in Task 12).
	challengeToken := "challenge-" + t.Name()
	key := "mfa:challenge:" + challengeToken
	env.Valkey.HSet(t.Context(), key,
		"user_id", userID,
		"attempts_remaining", 5,
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

	// Session cookie set.
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "schlass_session" {
			session = c
		}
	}
	if session == nil || session.Value == "" {
		t.Fatal("no session cookie after successful challenge")
	}

	// login.succeeded audit row present.
	var ev string
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT event_type FROM audit_logs WHERE event_type = 'login.succeeded' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&ev); err != nil {
		t.Fatalf("login.succeeded audit row missing: %v", err)
	}
	if ev != "login.succeeded" {
		t.Fatal("login.succeeded audit row missing")
	}

	// mfa.challenge_succeeded audit row present.
	if err := env.Pool.QueryRow(t.Context(),
		`SELECT event_type FROM audit_logs WHERE event_type = 'mfa.challenge_succeeded' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&ev); err != nil {
		t.Fatalf("mfa.challenge_succeeded audit row missing: %v", err)
	}
	if ev != "mfa.challenge_succeeded" {
		t.Fatal("mfa.challenge_succeeded audit row missing")
	}

	// Challenge token should be deleted.
	exists, _ := env.Valkey.Exists(t.Context(), key).Result()
	if exists != 0 {
		t.Fatal("challenge token should be deleted after success")
	}
}

func TestMfaChallenge_TOTP_Replay_Rejected(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	userID, secret := enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")

	code, _ := totp.GenerateCode(secret, time.Now())
	body, _ := json.Marshal(map[string]string{"code": code})

	for _, label := range []string{"first", "replay"} {
		tok := "chal-" + label
		key := "mfa:challenge:" + tok
		env.Valkey.HSet(t.Context(), key,
			"user_id", userID, "attempts_remaining", 5)
		env.Valkey.Expire(t.Context(), key, 120)

		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "schlass_mfa_challenge", Value: tok})
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)

		if label == "first" && rec.Code != http.StatusOK {
			t.Fatalf("first attempt: want 200, got %d", rec.Code)
		}
		if label == "replay" && rec.Code == http.StatusOK {
			t.Fatal("replay of same code should be rejected (counter advance gate)")
		}
	}
}

func TestMfaChallenge_MaxAttempts(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Close()
	userID, _ := enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")

	tok := "chal-max"
	key := "mfa:challenge:" + tok
	env.Valkey.HSet(t.Context(), key,
		"user_id", userID, "attempts_remaining", 5)
	env.Valkey.Expire(t.Context(), key, 120)

	badBody, _ := json.Marshal(map[string]string{"code": "000000"})
	for i := 0; i < 5; i++ {
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(badBody))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "schlass_mfa_challenge", Value: tok})
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, rec.Code)
		}
	}
	// 6th attempt — challenge token should already be gone.
	exists, _ := env.Valkey.Exists(t.Context(), key).Result()
	if exists != 0 {
		t.Fatal("challenge token should be deleted after 5 failed attempts")
	}
}
