//go:build integration

package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// exportManifest mirrors the shape written by the export API.
type exportManifest struct {
	ExportedAt     time.Time       `json:"exported_at"`
	TenantID       string          `json:"tenant_id"`
	SequenceRange  [2]int64        `json:"sequence_range"`
	RowHashAtStart string          `json:"row_hash_at_start"`
	RowHashAtEnd   string          `json:"row_hash_at_end"`
	AnchorProof    *exportAnchorProof `json:"anchor_proof"`
	Format         string          `json:"format"`
}

type exportAnchorProof struct {
	Backend    string    `json:"backend"`
	Ref        string    `json:"ref"`
	AnchoredAt time.Time `json:"anchored_at"`
	SequenceNo int64     `json:"sequence_no"`
}

// TestAuditExport_BundleShape seeds a few rows, hits the export API for
// each format, and asserts: (a) the response is a tar.gz, (b) it contains
// a manifest.json with the right shape, (c) it contains the data file.
func TestAuditExport_BundleShape(t *testing.T) {
	env := NewTestEnv(t)
	defer env.Cleanup()

	adminID := env.SeedAdmin(t, "export-test@example.com", "CorrectHorse42!")
	cookie := env.LoginAsAdmin(t, "export-test@example.com", "CorrectHorse42!")

	// Emit a few rows via the chain so sequence_no + row_hash are populated.
	for i := 0; i < 3; i++ {
		insertAuditViewerRow(t, env, "login.succeeded", &adminID, "export-test@example.com", nil, nil, "success")
	}
	// Emit a CAEP-mapped row so the caep export has something to write.
	insertAuditViewerRow(t, env, "session.revoked", &adminID, "export-test@example.com", ptr("user"), ptr(adminID.String()), "success")

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

			// Data file must be present.
			dataName := exportDataFilename(format)
			if _, ok := files[dataName]; !ok {
				t.Errorf("format=%s: data file %q missing from bundle", format, dataName)
			}
		})
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
