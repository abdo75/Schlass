// audit-lint walks Go AST under the package paths supplied on the
// command line, finds every audit-emit composite literal, and rejects
// any metadata-map literal whose key matches a name in denylist.txt.
//
// REQ-AUD-011 (M2): metadata is the only freeform extension surface on
// audit_logs. The schema-level PII closure (drop actor_email, coarsen
// IPs) buys nothing if call sites can shove a "password" key into
// metadata. This linter is the static gate.
//
// Usage:
//   go run ./tools/audit-lint ./internal/...
//
// Exit codes:
//   0 — clean
//   1 — at least one denied key found (lines printed to stderr)
//   2 — invocation / loader error
package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/tools/go/packages"
)

// findDenylist locates denylist.txt next to this main.go regardless of
// the cwd the tool was invoked from. Falls back to the current working
// directory's tools/audit-lint/ path so `go run ./tools/audit-lint`
// works when this binary is rebuilt elsewhere.
func findDenylist() (string, error) {
	if _, file, _, ok := runtime.Caller(0); ok {
		candidate := filepath.Join(filepath.Dir(file), "denylist.txt")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, "tools", "audit-lint", "denylist.txt")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		candidate = filepath.Join(cwd, "denylist.txt")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("denylist.txt not found")
}

func loadDenylist(path string) (map[string]struct{}, error) {
	// gosec G304: path is resolved by findDenylist from build-time
	// constants (runtime.Caller / project layout), never untrusted input.
	raw, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{})
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = struct{}{}
	}
	return out, nil
}

type violation struct {
	pos token.Position
	key string
	in  string // function or call name where the metadata literal sits
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"./..."}
	}

	denylistPath, err := findDenylist()
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit-lint:", err)
		os.Exit(2)
	}
	denied, err := loadDenylist(denylistPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit-lint: load denylist:", err)
		os.Exit(2)
	}

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Env:  os.Environ(),
	}
	pkgs, err := packages.Load(cfg, args...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit-lint: load packages:", err)
		os.Exit(2)
	}
	if packages.PrintErrors(pkgs) > 0 {
		os.Exit(2)
	}

	var violations []violation
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				if !looksLikeAuditEvent(lit) {
					return true
				}
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					ident, ok := kv.Key.(*ast.Ident)
					if !ok || ident.Name != "Metadata" {
						continue
					}
					mapLit, ok := kv.Value.(*ast.CompositeLit)
					if !ok {
						continue
					}
					for _, el := range mapLit.Elts {
						mkv, ok := el.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						bl, ok := mkv.Key.(*ast.BasicLit)
						if !ok || bl.Kind != token.STRING {
							continue
						}
						key := strings.Trim(bl.Value, `"`)
						if _, bad := denied[key]; bad {
							violations = append(violations, violation{
								pos: pkg.Fset.Position(bl.Pos()),
								key: key,
								in:  pkg.PkgPath,
							})
						}
					}
				}
				return true
			})
		}
	}

	if len(violations) == 0 {
		return
	}
	for _, v := range violations {
		fmt.Fprintf(os.Stderr,
			"audit-lint: %s:%d:%d: metadata key %q is on the REQ-AUD-011 denylist (package %s)\n",
			v.pos.Filename, v.pos.Line, v.pos.Column, v.key, v.in,
		)
	}
	fmt.Fprintf(os.Stderr, "audit-lint: %d violation(s); see denylist at tools/audit-lint/denylist.txt\n", len(violations))
	os.Exit(1)
}

// looksLikeAuditEvent identifies composite literals shaped like an
// audit.Event or *.Event so we don't have to rely on type info (which
// is expensive to load) to spot the metadata field. We accept any
// composite literal whose Type is a selector expression ending in
// "Event" — this matches `audit.Event{...}`. False positives outside
// the audit package are extremely rare and harmless: the linter only
// fires when the literal also has a Metadata field whose value is a
// map literal.
func looksLikeAuditEvent(lit *ast.CompositeLit) bool {
	switch t := lit.Type.(type) {
	case *ast.SelectorExpr:
		return t.Sel != nil && t.Sel.Name == "Event"
	case *ast.Ident:
		return t.Name == "Event"
	}
	return false
}
