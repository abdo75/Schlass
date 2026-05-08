package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeBundleFile writes a tar.gz with the given files to a temp path.
func makeBundleFile(t *testing.T, files map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		hdr := &tar.Header{
			Name:    name,
			Mode:    0o644,
			Size:    int64(len(data)),
			ModTime: time.Now(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func makeManifest(format string) []byte {
	m := Manifest{
		ExportedAt:     time.Now().UTC(),
		TenantID:       "00000000-0000-0000-0000-000000000000",
		SequenceRange:  [2]int64{1, 3},
		RowHashAtStart: "aabbccdd",
		RowHashAtEnd:   "eeff0011",
		Format:         format,
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return b
}

func TestVerifyBundle_CSV(t *testing.T) {
	csv := []byte("id,created_at,event_type,outcome\nrow1,2026-01-01,login.succeeded,success\nrow2,2026-01-02,login.failed,failure\n")
	path := makeBundleFile(t, map[string][]byte{
		"audit-log.csv":  csv,
		"manifest.json":  makeManifest("csv"),
	})
	result, err := VerifyBundle(path, "")
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if result.RowCount != 2 {
		t.Errorf("RowCount = %d, want 2", result.RowCount)
	}
}

func TestVerifyBundle_JSONL(t *testing.T) {
	lines := `{"id":"1","event_type":"login.succeeded","outcome":"success"}` + "\n" +
		`{"id":"2","event_type":"session.revoked","outcome":"success"}` + "\n"
	path := makeBundleFile(t, map[string][]byte{
		"audit-log.jsonl": []byte(lines),
		"manifest.json":   makeManifest("jsonl"),
	})
	result, err := VerifyBundle(path, "")
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if result.RowCount != 2 {
		t.Errorf("RowCount = %d, want 2", result.RowCount)
	}
}

func TestVerifyBundle_CAEP_ClaimsLines(t *testing.T) {
	// Export without signing key produces JSON claims maps, not JWS.
	line1, _ := json.Marshal(map[string]any{"iss": "https://auth.example.com", "jti": "abc"})
	line2, _ := json.Marshal(map[string]any{"iss": "https://auth.example.com", "jti": "def"})
	data := append(line1, '\n')
	data = append(data, line2...)
	data = append(data, '\n')

	path := makeBundleFile(t, map[string][]byte{
		"audit-log.set.jsonl": data,
		"manifest.json":       makeManifest("caep"),
	})
	result, err := VerifyBundle(path, "")
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if result.RowCount != 2 {
		t.Errorf("RowCount = %d, want 2", result.RowCount)
	}
}

func TestVerifyBundle_MissingManifest(t *testing.T) {
	path := makeBundleFile(t, map[string][]byte{
		"audit-log.csv": []byte("id\n"),
	})
	if _, err := VerifyBundle(path, ""); err == nil {
		t.Error("expected error for missing manifest.json, got nil")
	}
}

func TestVerifyBundle_UnknownFormat(t *testing.T) {
	m := Manifest{Format: "unknown"}
	mb, _ := json.Marshal(m)
	path := makeBundleFile(t, map[string][]byte{
		"audit-log.unknown": []byte("data"),
		"manifest.json":     mb,
	})
	if _, err := VerifyBundle(path, ""); err == nil {
		t.Error("expected error for unknown format, got nil")
	}
}
