// Tests for the audit-lint static analyzer. Each fixture is a tiny
// stand-alone module under testdata/ so the parent module's package
// graph isn't polluted by the deliberately denylisted "password" key.
//
// We invoke the linter as a subprocess against each fixture's directory
// and assert exit code + stderr shape.
package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildLint compiles the linter into a temp binary once per test
// process. Subsequent runLint calls reuse the same binary so cross-module
// fixture invocations work (the fixtures have their own go.mod).
var lintBinary string

func buildLint(t *testing.T) string {
	t.Helper()
	if lintBinary != "" {
		return lintBinary
	}
	root, err := projectRoot()
	if err != nil {
		t.Fatalf("locate project root: %v", err)
	}
	tmp, err := os.CreateTemp("", "audit-lint-*")
	if err != nil {
		t.Fatalf("tempfile: %v", err)
	}
	_ = tmp.Close()
	// gosec G204: hardcoded test-only invocation; no untrusted input.
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", tmp.Name(), "./tools/audit-lint") //nolint:gosec
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build linter: %v\nstderr: %s", err, stderr.String())
	}
	lintBinary = tmp.Name()
	t.Cleanup(func() { _ = os.Remove(lintBinary); lintBinary = "" })
	return lintBinary
}

// runLint runs the linter binary against testdata/<fixture> with the
// cwd set to that directory. Returns exit code + stderr.
func runLint(t *testing.T, fixture string) (int, string) {
	t.Helper()
	bin := buildLint(t)
	root, err := projectRoot()
	if err != nil {
		t.Fatalf("locate project root: %v", err)
	}
	fixtureDir := filepath.Join(root, "tools", "audit-lint", "testdata", fixture)
	if _, err := os.Stat(fixtureDir); err != nil {
		t.Fatalf("fixture %q missing: %v", fixture, err)
	}
	// gosec G204: bin is the just-built test binary; no tainted input.
	cmd := exec.CommandContext(t.Context(), bin, ".") //nolint:gosec
	cmd.Dir = fixtureDir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("run linter: %v\nstderr: %s", err, stderr.String())
		}
	}
	return exitCode, stderr.String()
}

func projectRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for d := cwd; d != "/"; d = filepath.Dir(d) {
		// The parent module owns tools/audit-lint; the fixtures have
		// their own (sub-)go.mod, so we walk past those.
		if _, err := os.Stat(filepath.Join(d, "tools", "audit-lint", "main.go")); err == nil {
			return d, nil
		}
	}
	return "", os.ErrNotExist
}

func TestAuditLint_CleanFixture_ExitsZero(t *testing.T) {
	code, stderr := runLint(t, "clean")
	if code != 0 {
		t.Errorf("clean fixture: exit code = %d, want 0\nstderr: %s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("clean fixture: stderr should be empty, got %q", stderr)
	}
}

func TestAuditLint_DirtyFixture_ExitsNonZero(t *testing.T) {
	code, stderr := runLint(t, "dirty")
	if code == 0 {
		t.Fatalf("dirty fixture: exit code = 0, want non-zero\nstderr: %s", stderr)
	}
	if !strings.Contains(stderr, `metadata key "password"`) {
		t.Errorf("dirty fixture: stderr missing password violation message\ngot: %s", stderr)
	}
	if !strings.Contains(stderr, "REQ-AUD-011") {
		t.Errorf("dirty fixture: stderr should cite REQ-AUD-011\ngot: %s", stderr)
	}
	if !strings.Contains(stderr, "main.go") {
		t.Errorf("dirty fixture: stderr should reference the offending file\ngot: %s", stderr)
	}
}

// Builder-form coverage: NewEvent(...).WithMetadata(map[string]any{...}).Build().
// The original linter only saw composite literals; missing this path
// would let M3+ call sites smuggle "password" past the gate.

func TestAuditLint_CleanBuilderFixture_ExitsZero(t *testing.T) {
	code, stderr := runLint(t, "clean_builder")
	if code != 0 {
		t.Errorf("clean_builder fixture: exit code = %d, want 0\nstderr: %s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("clean_builder fixture: stderr should be empty, got %q", stderr)
	}
}

func TestAuditLint_DirtyBuilderFixture_ExitsNonZero(t *testing.T) {
	code, stderr := runLint(t, "dirty_builder")
	if code == 0 {
		t.Fatalf("dirty_builder fixture: exit code = 0, want non-zero\nstderr: %s", stderr)
	}
	if !strings.Contains(stderr, `metadata key "password"`) {
		t.Errorf("dirty_builder fixture: stderr missing password violation\ngot: %s", stderr)
	}
	if !strings.Contains(stderr, "REQ-AUD-011") {
		t.Errorf("dirty_builder fixture: stderr should cite REQ-AUD-011\ngot: %s", stderr)
	}
}
