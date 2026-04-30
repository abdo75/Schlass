//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

type tokenFailureAuditRow struct {
	ActorID    sql.NullString
	ActorEmail sql.NullString
	TargetType string
	TargetID   string
	ClientID   sql.NullString
	IPAddress  string
	Metadata   map[string]any
}

func readTokenFailureAudit(t *testing.T, env *TestEnv, eventType string) tokenFailureAuditRow {
	t.Helper()

	var (
		row          tokenFailureAuditRow
		metadataJSON []byte
	)
	err := env.Pool.QueryRow(context.Background(), `
		SELECT actor_id::text,
		       actor_email,
		       target_type,
		       target_id,
		       client_id::text,
		       ip_address::text,
		       metadata
		FROM audit_logs
		WHERE event_type = $1 AND outcome = 'failure'
		ORDER BY created_at DESC
		LIMIT 1
	`, eventType).Scan(
		&row.ActorID,
		&row.ActorEmail,
		&row.TargetType,
		&row.TargetID,
		&row.ClientID,
		&row.IPAddress,
		&metadataJSON,
	)
	if err != nil {
		t.Fatalf("readTokenFailureAudit(%q): %v", eventType, err)
	}
	if err := json.Unmarshal(metadataJSON, &row.Metadata); err != nil {
		t.Fatalf("unmarshal audit metadata: %v", err)
	}
	return row
}

func lookupAuthCodeFamilyID(t *testing.T, env *TestEnv, code string) string {
	t.Helper()

	sum := sha256.Sum256([]byte(code))
	codeHash := fmt.Sprintf("%x", sum[:])
	var familyID string
	if err := env.Pool.QueryRow(context.Background(),
		`SELECT family_id::text FROM authorization_codes WHERE code_hash = $1`,
		codeHash,
	).Scan(&familyID); err != nil {
		t.Fatalf("lookupAuthCodeFamilyID: %v", err)
	}
	return familyID
}

func assertTokenFailureAudit(
	t *testing.T,
	env *TestEnv,
	eventType string,
	clientID string,
	familyID string,
	wantActorID string,
	wantActorEmail string,
) tokenFailureAuditRow {
	t.Helper()

	if n := countAuditRows(t, env, eventType, "failure"); n != 1 {
		t.Fatalf("expected 1 %s audit row, got %d", eventType, n)
	}

	row := readTokenFailureAudit(t, env, eventType)
	if !row.ActorID.Valid {
		t.Fatalf("%s actor_id missing", eventType)
	}
	if row.ActorID.String != wantActorID {
		t.Fatalf("%s actor_id=%q want %q", eventType, row.ActorID.String, wantActorID)
	}
	gotActorEmail := ""
	if row.ActorEmail.Valid {
		gotActorEmail = row.ActorEmail.String
	}
	if gotActorEmail != wantActorEmail {
		t.Fatalf("%s actor_email=%q want %q", eventType, gotActorEmail, wantActorEmail)
	}
	if row.TargetType != "client" {
		t.Fatalf("%s target_type=%q want client", eventType, row.TargetType)
	}
	if row.TargetID != clientID {
		t.Fatalf("%s target_id=%q want %q", eventType, row.TargetID, clientID)
	}
	if !row.ClientID.Valid {
		t.Fatalf("%s client_id missing", eventType)
	}
	if row.ClientID.String != clientID {
		t.Fatalf("%s client_id=%q want %q", eventType, row.ClientID.String, clientID)
	}
	if row.IPAddress == "" {
		t.Fatalf("%s ip_address empty", eventType)
	}
	gotFamilyID, ok := row.Metadata["family_id"].(string)
	if !ok || gotFamilyID == "" {
		t.Fatalf("%s metadata.family_id missing: %#v", eventType, row.Metadata["family_id"])
	}
	if gotFamilyID != familyID {
		t.Fatalf("%s metadata.family_id=%q want %q", eventType, gotFamilyID, familyID)
	}
	return row
}

func TestToken_AuthorizationCodeFailureAudits(t *testing.T) {
	const (
		adminEmail = "admin@example.com"
		adminPass  = "CorrectHorse42!"
		redirect   = "https://rp.example.com/cb"
	)

	t.Run("client_mismatch", func(t *testing.T) {
		env := NewTestEnv(t)
		bootstrapKey(t, env)
		userID := env.SeedAdmin(t, adminEmail, adminPass)
		cookie := env.LoginAsAdmin(t, adminEmail, adminPass)

		clientA := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
		clientB := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
		verifier, challenge := pkceParams()
		code := runAuthorizeAndGetCode(t, env, cookie, clientA, redirect, "openid profile", verifier, challenge)
		familyID := lookupAuthCodeFamilyID(t, env, code)

		params := buildTokenParams(clientB, code, redirect, verifier)
		rec := doTokenRequest(t, env, params)

		assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")
		assertTokenFailureAudit(t, env, "oidc.code.client_mismatch", clientB, familyID, userID.String(), "")
	})

	t.Run("redirect_mismatch", func(t *testing.T) {
		env := NewTestEnv(t)
		bootstrapKey(t, env)
		userID := env.SeedAdmin(t, adminEmail, adminPass)
		cookie := env.LoginAsAdmin(t, adminEmail, adminPass)

		clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
		verifier, challenge := pkceParams()
		code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)
		familyID := lookupAuthCodeFamilyID(t, env, code)

		params := buildTokenParams(clientID, code, "https://different.example.com/cb", verifier)
		rec := doTokenRequest(t, env, params)

		assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")
		assertTokenFailureAudit(t, env, "oidc.code.redirect_mismatch", clientID, familyID, userID.String(), "")
	})

	t.Run("pkce_mismatch", func(t *testing.T) {
		env := NewTestEnv(t)
		bootstrapKey(t, env)
		userID := env.SeedAdmin(t, adminEmail, adminPass)
		cookie := env.LoginAsAdmin(t, adminEmail, adminPass)

		clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
		verifier, challenge := pkceParams()
		code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)
		familyID := lookupAuthCodeFamilyID(t, env, code)

		params := buildTokenParams(clientID, code, redirect, "wrong-verifier-that-does-not-match-challenge")
		rec := doTokenRequest(t, env, params)

		assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")
		assertTokenFailureAudit(t, env, "oidc.code.pkce_mismatch", clientID, familyID, userID.String(), "")
	})

	t.Run("user_not_found", func(t *testing.T) {
		env := NewTestEnv(t)
		bootstrapKey(t, env)
		_ = env.SeedAdmin(t, adminEmail, adminPass)
		cookie := env.LoginAsAdmin(t, adminEmail, adminPass)

		clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
		verifier, challenge := pkceParams()
		code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)
		familyID := lookupAuthCodeFamilyID(t, env, code)

		sum := sha256.Sum256([]byte(code))
		codeHash := fmt.Sprintf("%x", sum[:])
		missingUserID := uuid.New()
		if _, err := env.MigrationsPool.Exec(context.Background(),
			`ALTER TABLE authorization_codes DROP CONSTRAINT authorization_codes_user_id_fkey`,
		); err != nil {
			t.Fatalf("drop authorization_codes_user_id_fkey: %v", err)
		}
		if _, err := env.MigrationsPool.Exec(context.Background(),
			`UPDATE authorization_codes SET user_id = $1 WHERE code_hash = $2`,
			missingUserID, codeHash,
		); err != nil {
			t.Fatalf("rewrite authorization_codes.user_id: %v", err)
		}

		params := buildTokenParams(clientID, code, redirect, verifier)
		rec := doTokenRequest(t, env, params)

		assertTokenError(t, rec, http.StatusBadRequest, "invalid_grant")
		row := assertTokenFailureAudit(t, env, "oidc.code.user_not_found", clientID, familyID, missingUserID.String(), "")
		gotUserID, ok := row.Metadata["user_id"].(string)
		if !ok || gotUserID != missingUserID.String() {
			t.Fatalf("oidc.code.user_not_found metadata.user_id=%#v want %q", row.Metadata["user_id"], missingUserID.String())
		}
	})

	t.Run("grant_removed", func(t *testing.T) {
		env := NewTestEnv(t)
		bootstrapKey(t, env)
		userID := env.SeedAdmin(t, adminEmail, adminPass)
		cookie := env.LoginAsAdmin(t, adminEmail, adminPass)

		clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
		verifier, challenge := pkceParams()
		code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)
		familyID := lookupAuthCodeFamilyID(t, env, code)

		if _, err := env.Pool.Exec(context.Background(),
			`UPDATE clients SET allowed_grant_types = $1 WHERE id = $2`,
			[]string{"refresh_token"}, clientID,
		); err != nil {
			t.Fatalf("remove authorization_code grant: %v", err)
		}

		params := buildTokenParams(clientID, code, redirect, verifier)
		rec := doTokenRequest(t, env, params)

		assertTokenError(t, rec, http.StatusBadRequest, "unauthorized_client")
		assertTokenFailureAudit(t, env, "oidc.code.grant_removed", clientID, familyID, userID.String(), adminEmail)
	})

	t.Run("scope_removed", func(t *testing.T) {
		env := NewTestEnv(t)
		bootstrapKey(t, env)
		userID := env.SeedAdmin(t, adminEmail, adminPass)
		cookie := env.LoginAsAdmin(t, adminEmail, adminPass)

		clientID := seedTokenClient(t, env, redirect, []string{"openid", "profile"})
		verifier, challenge := pkceParams()
		code := runAuthorizeAndGetCode(t, env, cookie, clientID, redirect, "openid profile", verifier, challenge)
		familyID := lookupAuthCodeFamilyID(t, env, code)

		if _, err := env.Pool.Exec(context.Background(),
			`UPDATE clients SET allowed_scopes = $1 WHERE id = $2`,
			[]string{"email"}, clientID,
		); err != nil {
			t.Fatalf("remove requested scopes: %v", err)
		}

		params := buildTokenParams(clientID, code, redirect, verifier)
		rec := doTokenRequest(t, env, params)

		assertTokenError(t, rec, http.StatusBadRequest, "invalid_scope")
		row := assertTokenFailureAudit(t, env, "oidc.code.scope_removed", clientID, familyID, userID.String(), adminEmail)

		requestedScopes, ok := row.Metadata["requested_scopes"].([]any)
		if !ok || len(requestedScopes) != 2 || requestedScopes[0] != "openid" || requestedScopes[1] != "profile" {
			t.Fatalf("oidc.code.scope_removed metadata.requested_scopes=%#v", row.Metadata["requested_scopes"])
		}
		allowedScopes, ok := row.Metadata["allowed_scopes"].([]any)
		if !ok || len(allowedScopes) != 1 || allowedScopes[0] != "email" {
			t.Fatalf("oidc.code.scope_removed metadata.allowed_scopes=%#v", row.Metadata["allowed_scopes"])
		}
	})
}
