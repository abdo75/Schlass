//go:build integration

package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	auditapi "github.com/abdo75/Schlass/internal/audit"
	"github.com/abdo75/Schlass/internal/signingkeys"
)

// exportManifest mirrors the shape written by the export API.
type exportManifest struct {
	ExportedAt     time.Time          `json:"exported_at"`
	TenantID       string             `json:"tenant_id"`
	SequenceRange  [2]int64           `json:"sequence_range"`
	RowHashAtStart string             `json:"row_hash_at_start"`
	RowHashAtEnd   string             `json:"row_hash_at_end"`
	AnchorProof    *exportAnchorProof `json:"anchor_proof"`
	Format         string             `json:"format"`
}

type exportAnchorProof struct {
	Backend    string    `json:"backend"`
	Ref        string    `json:"ref"`
	AnchoredAt time.Time `json:"anchored_at"`
	SequenceNo int64     `json:"sequence_no"`
}

// emitChainRow emits one audit row through the real chain (Emit → chain.Append)
// so sequence_no and row_hash are populated by the store. This is required for
// RowHashAtEnd to be non-empty in the manifest and for the CAEP export to have
// a valid signing key context.
func emitChainRow(t *testing.T, env *TestEnv, actorID *uuid.UUID, eventType string, targetType, targetID *string, outcome string) {
	t.Helper()
	store := auditapi.NewStore()
	ctx := context.Background()
	tx, err := env.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("emitChainRow begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	evt := auditapi.Event{
		EventType: eventType,
		ActorID:   actorID,
		Outcome:   outcome,
	}
	if targetType != nil {
		evt.TargetType = *targetType
	}
	if targetID != nil {
		evt.TargetID = *targetID
	}
	if err := store.Emit(ctx, tx, evt); err != nil {
		t.Fatalf("emitChainRow emit: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("emitChainRow commit: %v", err)
	}
}

// TestAuditExport_BundleShape seeds a few rows, hits the export API for
// each format, and asserts: (a) the response is a tar.gz, (b) it contains
// a manifest.json with the right shape, (c) it contains the data file.
// For caep: each line is a valid JWS; decoded payload has iss + events URN + jti UUID.
// For all formats: manifest.RowHashAtEnd is non-empty (chain rows were used).
func TestAuditExport_BundleShape(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	adminID := env.SeedAdmin(t, "export-test@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "export-test@example.com", "CorrectHorse42!")

	// Bootstrap a signing key so CAEP export can sign SETs.
	bootstrapSigningKey(t, env)

	// Emit rows via the chain so sequence_no + row_hash are populated.
	for i := 0; i < 3; i++ {
		emitChainRow(t, env, &adminID, "login.succeeded", nil, nil, "success")
	}
	// Emit a CAEP-mapped row so the caep export has something to write.
	emitChainRow(t, env, &adminID, "session.revoked", ptr("user"), ptr(adminID.String()), "success")

	for _, format := range []string{"csv", "jsonl", "caep"} {
		t.Run(format, func(t *testing.T) {
			// Export requires recent MFA step-up.
			if err := env.SessionStore.MarkMFAVerified(t.Context(), cookie.Value); err != nil {
				t.Fatalf("MarkMFAVerified: %v", err)
			}
			rec := postExport(t, env, cookie, format)
			if rec.Code != http.StatusOK {
				t.Fatalf("format=%s: status %d: %s", format, rec.Code, rec.Body.String())
			}
			ct := rec.Header().Get("Content-Type")
			if ct != "application/gzip" {
				t.Errorf("format=%s: Content-Type = %q, want application/gzip", format, ct)
			}

			files := extractTarGz(t, rec.Body.Bytes())

			// manifest.json must always be present.
			mBytes, ok := files["manifest.json"]
			if !ok {
				t.Fatalf("format=%s: manifest.json missing from bundle", format)
			}
			var manifest exportManifest
			if err := json.Unmarshal(mBytes, &manifest); err != nil {
				t.Fatalf("format=%s: parse manifest: %v", format, err)
			}
			if manifest.Format != format {
				t.Errorf("format=%s: manifest.format = %q, want %q", format, manifest.Format, format)
			}
			if manifest.TenantID == "" {
				t.Errorf("format=%s: manifest.tenant_id empty", format)
			}
			// Chain rows must have populated row_hash so RowHashAtEnd is non-empty.
			if manifest.RowHashAtEnd == "" {
				t.Errorf("format=%s: manifest.row_hash_at_end empty — rows not chain-emitted?", format)
			}

			// Data file must be present.
			dataName := exportDataFilename(format)
			dataBytes, ok := files[dataName]
			if !ok {
				t.Errorf("format=%s: data file %q missing from bundle", format, dataName)
			}

			// CAEP-specific: each line must be a valid JWS with correct claims.
			if format == "caep" {
				assertCAEPLines(t, dataBytes, env.Cfg.SchlassPublicURL)
			}
		})
	}
}

// assertCAEPLines parses audit-log.set.jsonl line-by-line and asserts:
//   - each non-empty line has exactly 3 dot-separated base64url segments (JWS)
//   - the payload (middle segment) decodes to JSON with iss == wantIssuer
//   - events map contains a CAEP URN key
//   - jti parses as UUID
func assertCAEPLines(t *testing.T, data []byte, wantIssuer string) {
	t.Helper()
	content := strings.TrimSpace(string(data))
	if content == "" {
		t.Error("caep: audit-log.set.jsonl is empty — no CAEP-mapped rows exported")
		return
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ".")
		if len(parts) != 3 {
			t.Errorf("caep line %d: want 3 JWS segments, got %d: %q", i+1, len(parts), line[:min(len(line), 80)])
			continue
		}
		// Decode the payload (middle segment).
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Errorf("caep line %d: base64 decode payload: %v", i+1, err)
			continue
		}
		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Errorf("caep line %d: parse payload JSON: %v", i+1, err)
			continue
		}
		// iss must match the issuer.
		iss, _ := claims["iss"].(string)
		if iss != wantIssuer {
			t.Errorf("caep line %d: iss = %q, want %q", i+1, iss, wantIssuer)
		}
		// events map must be present and non-empty.
		events, _ := claims["events"].(map[string]any)
		if len(events) == 0 {
			t.Errorf("caep line %d: events map missing or empty", i+1)
		} else {
			for urn := range events {
				if !strings.HasPrefix(urn, "https://") {
					t.Errorf("caep line %d: events URN %q does not look like a CAEP URN", i+1, urn)
				}
			}
		}
		// jti must parse as UUID.
		jti, _ := claims["jti"].(string)
		if _, err := uuid.Parse(jti); err != nil {
			t.Errorf("caep line %d: jti %q is not a UUID: %v", i+1, jti, err)
		}
	}
}

// bootstrapSigningKey ensures a signing key exists in the test DB so the CAEP
// export path can fetch an active key. Uses signingkeys.Bootstrap which is
// idempotent — safe to call when a key already exists.
func bootstrapSigningKey(t *testing.T, env *TestEnv) {
	t.Helper()
	if err := signingkeys.Bootstrap(context.Background(), env.Pool, auditapi.NewStore(), env.Cfg.EncryptionKey); err != nil {
		t.Fatalf("bootstrapSigningKey: %v", err)
	}
}

// TestAuditExport_InvalidFormat checks that format validation rejects
// unknown values.
func TestAuditExport_InvalidFormat(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()
	env.SeedAdmin(t, "fmt@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "fmt@example.com", "CorrectHorse42!")
	if err := env.SessionStore.MarkMFAVerified(t.Context(), cookie.Value); err != nil {
		t.Fatalf("MarkMFAVerified: %v", err)
	}

	rec := postExport(t, env, cookie, "parquet")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func postExport(t *testing.T, env *TestEnv, cookie *http.Cookie, format string) *httptest.ResponseRecorder {
	t.Helper()
	body := bytes.NewBufferString(`{"since":"24h","view":"all","format":"` + format + `"}`)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/audit/export", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.Router.ServeHTTP(rec, req)
	return rec
}

func extractTarGz(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read %q: %v", hdr.Name, err)
		}
		files[hdr.Name] = b
	}
	return files
}

func exportDataFilename(format string) string {
	switch format {
	case "csv":
		return "audit-log.csv"
	case "jsonl":
		return "audit-log.jsonl"
	case "caep":
		return "audit-log.set.jsonl"
	default:
		return "audit-log." + format
	}
}
