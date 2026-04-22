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

type HIBPChecker struct {
	Endpoint string
	HTTPClient *http.Client
}

func (c *HIBPChecker) IsPwned(ctx context.Context, password string) (bool, error) {
	if c == nil {
		return false, nil
	}
	sum := sha1.Sum([]byte(password)) //nolint:gosec // G401: see file header — SHA-1 required by HIBP API.
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]

	url := c.Endpoint + "/" + prefix

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 1500 * time.Millisecond}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("hibp: build request: %w", err)
	}

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
