// REQ-AUD-031 (M2): the raw User-Agent header is never persisted. We
// parse it down to a coarse "Family/Major" string (e.g. "Firefox/126")
// before storing in client_ua_family. ParseUAFamily is the single sanctioned
// transform; emit sites read the request header, hand it here, and store
// only the return value.
package audit

import (
	"strconv"
	"strings"

	ua "github.com/mileusna/useragent"
)

// uaFamilyMaxLen caps the post-parse string so a malicious User-Agent
// header can't bloat the client_ua_family TEXT column with attacker-
// controlled bytes. 32 ASCII chars holds every real-world Family/Major
// (longest observed: "SamsungBrowser/123" at 18) with margin.
const uaFamilyMaxLen = 32

// ParseUAFamily compresses a raw User-Agent header into a
// "Family/Major" pair. Empty/unparseable input returns "".
//
// The mileusna/useragent library returns a free-form Version field
// (often "126.0.0.0"); we keep only the leading numeric segment so
// downstream cardinality stays bounded. The result is then validated
// against a narrow ASCII allowlist and capped at uaFamilyMaxLen bytes —
// a hostile UA whose Name token contains control bytes or non-ASCII
// rubbish is rejected entirely (column is nullable, so caller writes
// NULL) rather than persisted.
func ParseUAFamily(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed := ua.Parse(raw)
	family := parsed.Name
	if family == "" {
		return ""
	}
	out := family
	if major := majorVersion(parsed.Version); major != "" {
		out = family + "/" + major
	}
	if len(out) > uaFamilyMaxLen {
		return ""
	}
	if !isAllowedUAFamily(out) {
		return ""
	}
	return out
}

// isAllowedUAFamily restricts the parsed Family/Major to a narrow ASCII
// subset: letters, digits, space, and the punctuation that legitimately
// appears in browser/library names ("." for "OkHttp 4.12", "_" for
// "Mozilla_compatible", "-" for "PRE-RELEASE", "/" for the Family/Major
// separator we add ourselves). Everything else — including control
// characters, high-bit bytes, and shell metacharacters — fails closed.
func isAllowedUAFamily(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == ' ', c == '.', c == '_', c == '-', c == '/':
		default:
			return false
		}
	}
	return true
}

// majorVersion extracts the leading integer segment from a version
// string like "126.0.0.0" or "17.4". Returns "" if the version is
// missing or has no numeric prefix.
func majorVersion(v string) string {
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	if _, err := strconv.Atoi(v); err != nil {
		return ""
	}
	return v
}
