package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

const recoveryCodeCount = 10

const recoveryCodeHalfLen = 4

const recoveryCodeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

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
