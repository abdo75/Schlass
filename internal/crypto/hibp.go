// Package-level doc for this file — HIBP k-anonymity client.
package crypto

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // G505: SHA-1 is required by the HIBP k-anonymity API; not used as a crypto primitive.
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultHIBPEndpoint is the canonical production HIBP range API. Tests
// and offline dev override it via HIBPChecker.Endpoint.
const DefaultHIBPEndpoint = "https://api.pwnedpasswords.com/range"

// HIBPChecker queries the Have I Been Pwned range API to detect whether
// a candidate password appears in any published breach corpus (NIST SP
// 800-63B-4 §3.1.1.2). Uses k-anonymity: the password's SHA-1 hash is
// split into a 5-char prefix (sent over the wire) and a 35-char suffix
// (checked locally against the response). The plaintext password and
// its full hash never leave the process.
//
// A nil *HIBPChecker behaves as if checking is disabled — IsPwned
// always returns (false, nil). Callers must be nil-safe.
type HIBPChecker struct {
	// Endpoint is the range API base URL (no trailing slash). Empty
	// means use DefaultHIBPEndpoint.
	Endpoint string
	// HTTPClient is the client used for range requests. nil means use
	// a client with Timeout = 1500ms.
	HTTPClient *http.Client
}

// IsPwned returns true iff the password appears at least once in the
// HIBP corpus. On any network, HTTP, or parse error it returns
// (false, err) — callers SHOULD log the error but MUST fail-open
// (treat the password as not pwned). HIBP being down is not a reason
// to block every password change.
func (c *HIBPChecker) IsPwned(ctx context.Context, password string) (bool, error) {
	if c == nil {
		return false, nil
	}
	sum := sha1.Sum([]byte(password)) //nolint:gosec // G401: see file header — SHA-1 required by HIBP API.
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]

	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultHIBPEndpoint
	}
	url := endpoint + "/" + prefix

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 1500 * time.Millisecond}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("hibp: build request: %w", err)
	}
	// HIBP recommends the Add-Padding header to defeat traffic analysis
	// on the response size.
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "schlass-hibp/1")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("hibp: http: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hibp: unexpected status %d", resp.StatusCode)
	}

	// Each line: "SUFFIX:COUNT\r\n" — SUFFIX is 35 uppercase hex.
	scan := bufio.NewScanner(resp.Body)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" {
			continue
		}
		sep := strings.IndexByte(line, ':')
		if sep <= 0 {
			continue
		}
		if strings.EqualFold(line[:sep], suffix) {
			// Any non-zero count counts as pwned per NIST guidance.
			// Padding responses are count=0 and must NOT match.
			countStr := strings.TrimSpace(line[sep+1:])
			if countStr == "" || countStr == "0" {
				return false, nil
			}
			return true, nil
		}
	}
	if err := scan.Err(); err != nil {
		return false, fmt.Errorf("hibp: scan: %w", err)
	}
	return false, nil
}
