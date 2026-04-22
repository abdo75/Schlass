package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Memory      = 19 * 1024 // 19 MiB
	argon2Iterations  = 2
	argon2Parallelism = 1
	argon2SaltLength  = 16
	argon2KeyLength   = 32
)

const tempPasswordAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func GenerateTemporaryPassword() (string, error) {
	const length = 16
	alphabetLen := big.NewInt(int64(len(tempPasswordAlphabet)))
	for attempt := 0; attempt < 8; attempt++ {
		out := make([]byte, length)
		var hasUpper, hasDigit bool
		for i := 0; i < length; i++ {
			n, err := rand.Int(rand.Reader, alphabetLen)
			if err != nil {
				return "", fmt.Errorf("generate temporary password: %w", err)
			}
			c := tempPasswordAlphabet[n.Int64()]
			out[i] = c
			if c >= 'A' && c <= 'Z' {
				hasUpper = true
			}
			if c >= '0' && c <= '9' {
				hasDigit = true
			}
		}
		if hasUpper && hasDigit {
			return string(out), nil
		}
	}
	return "", fmt.Errorf("generate temporary password: 8 attempts failed to satisfy upper+digit policy")
}

func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		argon2Iterations,
		argon2Memory,
		argon2Parallelism,
		argon2KeyLength,
	)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Memory,
		argon2Iterations,
		argon2Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	salt, hash, memory, iterations, parallelism, keyLength, err := parsePHC(encodedHash)
	if err != nil {
		return false, err
	}

	computed := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		keyLength,
	)

	return subtle.ConstantTimeCompare(hash, computed) == 1, nil
}

func parsePHC(encoded string) (salt, hash []byte, memory, iterations uint32, parallelism uint8, keyLength uint32, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid hash format: expected 6 parts, got %d", len(parts))
	}

	if parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid version: %w", err)
	}

	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid parameters: %w", err)
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid salt encoding: %w", err)
	}

	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid hash encoding: %w", err)
	}

	return salt, hash, m, t, p, uint32(len(hash)), nil //nolint:gosec // G115: len() returns int >= 0, safe to convert to uint32
}
