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

// TestLastLoginAt_StampedOnAllPaths verifies that users.last_login_at is
// populated in the same PG tx as the login.succeeded audit row at every
// successful-authentication path: PostLogin (force-pw and no-MFA),
// PostChallenge (TOTP and recovery), and PostEnrollmentComplete (fresh
// enrollment branch only).
func TestLastLoginAt_StampedOnAllPaths(t *testing.T) {
	t.Run("PostLogin no-MFA default branch", func(t *testing.T) {
		env := NewTestEnv(t)
		defer env.Close()
		env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

		// Disable MFA so login drops into the legacy 200 path.
		if _, err := env.Pool.Exec(t.Context(),
			`UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`,
		); err != nil {
			t.Fatalf("disable mfa: %v", err)
		}

		userID := env.GetUserIDByEmail(t, "admin@example.com")

		// Confirm last_login_at starts NULL.
		var before *time.Time
		if err := env.Pool.QueryRow(t.Context(),
			`SELECT last_login_at FROM users WHERE id = $1`, userID,
		).Scan(&before); err != nil {
			t.Fatalf("select last_login_at before: %v", err)
		}
		if before != nil {
			t.Fatalf("last_login_at should be NULL before login, got %v", *before)
		}

		testStart := time.Now()

		body, _ := json.Marshal(map[string]string{
			"email": "admin@example.com", "password": "CorrectHorse1Battery",
		})
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("login: want 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var after *time.Time
		if err := env.Pool.QueryRow(t.Context(),
			`SELECT last_login_at FROM users WHERE id = $1`, userID,
		).Scan(&after); err != nil {
			t.Fatalf("select last_login_at after: %v", err)
		}
		if after == nil {
			t.Fatal("last_login_at should be non-NULL after login")
		}
		if after.Before(testStart) {
			t.Fatalf("last_login_at %v should be >= testStart %v", *after, testStart)
		}
	})

	t.Run("PostLogin force-pw branch", func(t *testing.T) {
		env := NewTestEnv(t)
		defer env.Close()
		env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")

		// Disable MFA so we can both create via the API and hit the force-pw branch cleanly.
		if _, err := env.Pool.Exec(t.Context(),
			`UPDATE instance_config SET value = 'false' WHERE key = 'mfa_required'`,
		); err != nil {
			t.Fatalf("disable mfa: %v", err)
		}

		// Admin creates a new user — receives a temporary password + force_password_change=true.
		adminCookie := env.LoginAsAdmin(t, "admin@example.com", "CorrectHorse1Battery")
		createBody, _ := json.Marshal(map[string]string{"email": "newuser@example.com", "role": "user"})
		createReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/users", bytes.NewReader(createBody))
		createReq.Header.Set("Content-Type", "application/json")
		createReq.Header.Set("Origin", "http://localhost:3000")
		createReq.AddCookie(adminCookie)
		createRec := httptest.NewRecorder()
		env.Router.ServeHTTP(createRec, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create user: want 201, got %d: %s", createRec.Code, createRec.Body.String())
		}
		var createResp struct {
			TemporaryPassword string `json:"temporary_password"`
		}
		if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
			t.Fatalf("decode create-user response: %v", err)
		}
		if createResp.TemporaryPassword == "" {
			t.Fatal("no temporary_password in create-user response")
		}

		userID := env.GetUserIDByEmail(t, "newuser@example.com")

		var before *time.Time
		if err := env.Pool.QueryRow(t.Context(),
			`SELECT last_login_at FROM users WHERE id = $1`, userID,
		).Scan(&before); err != nil {
			t.Fatalf("select last_login_at before: %v", err)
		}
		if before != nil {
			t.Fatalf("last_login_at should be NULL before login, got %v", *before)
		}

		testStart := time.Now()

		// Login with the temp password — force_password_change branch (200, no MFA gate).
		loginBody, _ := json.Marshal(map[string]string{
			"email": "newuser@example.com", "password": createResp.TemporaryPassword,
		})
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login", bytes.NewReader(loginBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("force-pw login: want 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var after *time.Time
		if err := env.Pool.QueryRow(t.Context(),
			`SELECT last_login_at FROM users WHERE id = $1`, userID,
		).Scan(&after); err != nil {
			t.Fatalf("select last_login_at after: %v", err)
		}
		if after == nil {
			t.Fatal("last_login_at should be non-NULL after force-pw login")
		}
		if after.Before(testStart) {
			t.Fatalf("last_login_at %v should be >= testStart %v", *after, testStart)
		}
	})

	t.Run("MFA challenge TOTP path", func(t *testing.T) {
		env := NewTestEnv(t)
		defer env.Close()
		userIDStr, secret := enrollTestUser(t, env, "admin@example.com", "CorrectHorse1Battery")

		// After enrollment completion last_login_at is stamped (fresh-enrollment
		// path); reset it to NULL so we can isolate the challenge stamp.
		if _, err := env.Pool.Exec(t.Context(),
			`UPDATE users SET last_login_at = NULL WHERE id = $1`, userIDStr,
		); err != nil {
			t.Fatalf("reset last_login_at: %v", err)
		}

		// Seed a challenge token in Valkey (simulates PostLogin's enrolled-user branch).
		challengeToken := "chal-totp-" + t.Name()
		key := "mfa:challenge:" + challengeToken
		env.Valkey.HSet(t.Context(), key,
			"user_id", userIDStr,
			"attempts_remaining", 5,
		)
		env.Valkey.Expire(t.Context(), key, 120)

		testStart := time.Now()

		code, _ := totp.GenerateCode(secret, time.Now())
		body, _ := json.Marshal(map[string]string{"code": code})
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "schlass_mfa_challenge", Value: challengeToken})
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("challenge: want 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var after *time.Time
		if err := env.Pool.QueryRow(t.Context(),
			`SELECT last_login_at FROM users WHERE id = $1`, userIDStr,
		).Scan(&after); err != nil {
			t.Fatalf("select last_login_at after: %v", err)
		}
		if after == nil {
			t.Fatal("last_login_at should be non-NULL after TOTP challenge")
		}
		if after.Before(testStart) {
			t.Fatalf("last_login_at %v should be >= testStart %v", *after, testStart)
		}
	})

	t.Run("MFA challenge recovery-code path", func(t *testing.T) {
		env := NewTestEnv(t)
		defer env.Close()
		userIDStr, _, codes := enrollAndCaptureRecoveryCodes(t, env, "admin@example.com", "CorrectHorse1Battery")
		if len(codes) == 0 {
			t.Fatal("no recovery codes captured")
		}

		// Reset last_login_at so we observe only the recovery-path stamp.
		if _, err := env.Pool.Exec(t.Context(),
			`UPDATE users SET last_login_at = NULL WHERE id = $1`, userIDStr,
		); err != nil {
			t.Fatalf("reset last_login_at: %v", err)
		}

		challengeToken := "chal-rec-" + t.Name()
		key := "mfa:challenge:" + challengeToken
		env.Valkey.HSet(t.Context(), key, "user_id", userIDStr, "attempts_remaining", 5)
		env.Valkey.Expire(t.Context(), key, 120)

		testStart := time.Now()

		body, _ := json.Marshal(map[string]string{"recovery_code": codes[0]})
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/challenge", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "schlass_mfa_challenge", Value: challengeToken})
		rec := httptest.NewRecorder()
		env.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("recovery challenge: want 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var after *time.Time
		if err := env.Pool.QueryRow(t.Context(),
			`SELECT last_login_at FROM users WHERE id = $1`, userIDStr,
		).Scan(&after); err != nil {
			t.Fatalf("select last_login_at after: %v", err)
		}
		if after == nil {
			t.Fatal("last_login_at should be non-NULL after recovery-code challenge")
		}
		if after.Before(testStart) {
			t.Fatalf("last_login_at %v should be >= testStart %v", *after, testStart)
		}
	})

	t.Run("MFA enrollment completion (fresh, no prior session)", func(t *testing.T) {
		env := NewTestEnv(t)
		defer env.Close()
		env.CompleteSetup(t, "admin@example.com", "CorrectHorse1Battery")
		userID := env.GetUserIDByEmail(t, "admin@example.com")

		// CompleteSetup may have left last_login_at NULL (setup doesn't go through
		// the login handler). Make the pre-state explicit.
		if _, err := env.Pool.Exec(t.Context(),
			`UPDATE users SET last_login_at = NULL WHERE id = $1`, userID,
		); err != nil {
			t.Fatalf("reset last_login_at: %v", err)
		}

		// Drive the fresh-enrollment path via the enrollment cookie (pre-session).
		// Keep the path free of any existing schlass_session so PostEnrollmentComplete
		// takes the !sessionAuthed branch and stamps last_login_at.
		token := "enroll-" + t.Name()
		key := "mfa:enroll:" + token
		env.Valkey.HSet(t.Context(), key, "user_id", userID.String())
		env.Valkey.Expire(t.Context(), key, 10*60)

		// /start
		startReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/start", nil)
		startReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
		startRec := httptest.NewRecorder()
		env.Router.ServeHTTP(startRec, startReq)
		if startRec.Code != http.StatusOK {
			t.Fatalf("enrollment start: want 200, got %d: %s", startRec.Code, startRec.Body.String())
		}
		var startOut struct {
			SecretBase32 string `json:"secret_base32"`
		}
		_ = json.Unmarshal(startRec.Body.Bytes(), &startOut)

		// /verify — should not stamp last_login_at yet.
		code, _ := totp.GenerateCode(startOut.SecretBase32, time.Now())
		vBody, _ := json.Marshal(map[string]string{"code": code})
		vReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/verify", bytes.NewReader(vBody))
		vReq.Header.Set("Content-Type", "application/json")
		vReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
		vRec := httptest.NewRecorder()
		env.Router.ServeHTTP(vRec, vReq)
		if vRec.Code != http.StatusOK {
			t.Fatalf("enrollment verify: want 200, got %d: %s", vRec.Code, vRec.Body.String())
		}

		// Still NULL before /complete.
		var midway *time.Time
		if err := env.Pool.QueryRow(t.Context(),
			`SELECT last_login_at FROM users WHERE id = $1`, userID,
		).Scan(&midway); err != nil {
			t.Fatalf("select last_login_at midway: %v", err)
		}
		if midway != nil {
			t.Fatalf("last_login_at should still be NULL before /complete, got %v", *midway)
		}

		testStart := time.Now()

		// /complete
		cBody, _ := json.Marshal(map[string]bool{"acknowledged": true})
		cReq := httptest.NewRequestWithContext(t.Context(), "POST", "/api/mfa/enrollment/complete", bytes.NewReader(cBody))
		cReq.Header.Set("Content-Type", "application/json")
		cReq.AddCookie(&http.Cookie{Name: "schlass_mfa_enroll", Value: token})
		cRec := httptest.NewRecorder()
		env.Router.ServeHTTP(cRec, cReq)
		if cRec.Code != http.StatusOK {
			t.Fatalf("enrollment complete: want 200, got %d: %s", cRec.Code, cRec.Body.String())
		}

		var after *time.Time
		if err := env.Pool.QueryRow(t.Context(),
			`SELECT last_login_at FROM users WHERE id = $1`, userID,
		).Scan(&after); err != nil {
			t.Fatalf("select last_login_at after: %v", err)
		}
		if after == nil {
			t.Fatal("last_login_at should be non-NULL after fresh enrollment /complete")
		}
		if after.Before(testStart) {
			t.Fatalf("last_login_at %v should be >= testStart %v", *after, testStart)
		}
	})
}
