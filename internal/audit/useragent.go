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

// ParseUAFamily compresses a raw User-Agent header into a
// "Family/Major" pair. Empty/unparseable input returns "".
//
// The mileusna/useragent library returns a free-form Version field
// (often "126.0.0.0"); we keep only the leading numeric segment so
// downstream cardinality stays bounded.
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
	major := majorVersion(parsed.Version)
	if major == "" {
		return family
	}
	return family + "/" + major
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
