// audit-lint walks Go AST under the package paths supplied on the
// command line, finds every audit-emit metadata map literal — both
// `audit.Event{Metadata: map[string]any{...}}` and the builder form
// `audit.NewEvent(...).WithMetadata(map[string]any{...})` — and rejects
// any key that matches a name in denylist.txt.
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
				switch node := n.(type) {
				case *ast.CompositeLit:
					if !looksLikeAuditEvent(node) {
						return true
					}
					mapLit := metadataMapFromEventLiteral(node)
					if mapLit == nil {
						return true
					}
					violations = append(violations, scanMetadataMap(mapLit, pkg, denied)...)
				case *ast.CallExpr:
					sel, ok := node.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel == nil || sel.Sel.Name != "WithMetadata" {
						return true
					}
					if len(node.Args) == 0 {
						return true
					}
					mapLit, ok := node.Args[0].(*ast.CompositeLit)
					if !ok {
						return true
					}
					if !looksLikeMetadataMap(mapLit) {
						return true
					}
					violations = append(violations, scanMetadataMap(mapLit, pkg, denied)...)
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

// metadataMapFromEventLiteral returns the map literal assigned to the
// Metadata field of an Event composite literal, or nil if the field is
// absent / not a literal map. Splits the Event-shape concern out of the
// inspector so the same scanMetadataMap pass works for both struct
// literals and the builder's WithMetadata call.
func metadataMapFromEventLiteral(lit *ast.CompositeLit) *ast.CompositeLit {
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
		return mapLit
	}
	return nil
}

// looksLikeMetadataMap accepts the map literal types we expect to see
// on the builder's WithMetadata argument: `map[string]any` and
// `map[string]string`. Without this gate the linter would chase any
// `WithMetadata(otherFunc())` call and confuse a non-literal arg for a
// missing-Type literal. Untyped composite literals (Type == nil), which
// only appear inside an outer map literal context, are also accepted to
// stay forgiving on rare nested-builder patterns.
func looksLikeMetadataMap(lit *ast.CompositeLit) bool {
	if lit.Type == nil {
		return true
	}
	mapType, ok := lit.Type.(*ast.MapType)
	if !ok {
		return false
	}
	keyIdent, ok := mapType.Key.(*ast.Ident)
	if !ok || keyIdent.Name != "string" {
		return false
	}
	switch v := mapType.Value.(type) {
	case *ast.Ident:
		return v.Name == "any" || v.Name == "string"
	case *ast.InterfaceType:
		// `map[string]interface{}` — the pre-Go-1.18 spelling of any.
		return v.Methods == nil || len(v.Methods.List) == 0
	}
	return false
}

// scanMetadataMap walks one map[string]... literal and emits a
// violation per denylisted string-literal key. Non-string keys (idents,
// constants) are intentionally skipped — the linter is a static gate on
// inline literals, not a type-resolution engine.
func scanMetadataMap(mapLit *ast.CompositeLit, pkg *packages.Package, denied map[string]struct{}) []violation {
	var out []violation
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
			out = append(out, violation{
				pos: pkg.Fset.Position(bl.Pos()),
				key: key,
				in:  pkg.PkgPath,
			})
		}
	}
	return out
}
