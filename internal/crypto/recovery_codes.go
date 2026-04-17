package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// recoveryCodeCount is the fixed batch size per the MFA design spec §4c.
const recoveryCodeCount = 10

// recoveryCodeHalfLen is the character count per half of the XXXX-XXXX
// format.
const recoveryCodeHalfLen = 4

// recoveryCodeAlphabet is base58 minus 0/O/I/l/1 (visually ambiguous chars),
// same alphabet as GenerateTemporaryPassword. Reused so users who've seen
// an admin-generated credential recognise the shape.
const recoveryCodeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// GenerateRecoveryCodes returns 10 single-use recovery codes in XXXX-XXXX
// format and their Argon2id hashes (same policy as password hashing). The
// plaintext is returned for one-time display to the user; only the hashes
// persist to the DB. Codes within a batch are guaranteed unique (rejection
// loop on collision, astronomically unlikely for 10 codes × 57^8 space).
//
// Each code carries ~46 bits of entropy (log2(57^8)), sufficient for a
// single-use mechanism behind a rate-limited endpoint.
func GenerateRecoveryCodes() (plaintext []string, hashes []string, err error) {
	plaintext = make([]string, 0, recoveryCodeCount)
	hashes = make([]string, 0, recoveryCodeCount)
	seen := make(map[string]bool, recoveryCodeCount)

	for len(plaintext) < recoveryCodeCount {
		code, err := randomRecoveryCode()
		if err != nil {
			return nil, nil, fmt.Errorf("generate recovery code: %w", err)
		}
		if seen[code] {
			continue
		}
		seen[code] = true

		hash, err := HashPassword(code)
		if err != nil {
			return nil, nil, fmt.Errorf("hash recovery code: %w", err)
		}

		plaintext = append(plaintext, code)
		hashes = append(hashes, hash)
	}
	return plaintext, hashes, nil
}

func randomRecoveryCode() (string, error) {
	// Draw 2 × 4 chars from the alphabet. Use crypto/rand via a 4-byte big-
	// endian uint32 per half, then reduce into the alphabet with modulo —
	// modulo bias is negligible for a 57-char alphabet and a 2^32 source.
	buf := make([]byte, 4)
	code := make([]byte, 0, 9) // 4 + dash + 4
	for half := 0; half < 2; half++ {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		raw := binary.BigEndian.Uint32(buf)
		for i := 0; i < recoveryCodeHalfLen; i++ {
			idx := int(raw % uint32(len(recoveryCodeAlphabet)))
			code = append(code, recoveryCodeAlphabet[idx])
			raw /= uint32(len(recoveryCodeAlphabet))
		}
		if half == 0 {
			code = append(code, '-')
		}
	}
	return string(code), nil
}
