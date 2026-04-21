// Symmetric encryption. v1 format: [0x01][wrapped DEK 60B][sealed data].
// Envelope-encrypted (DEK-per-message, DEK wrapped under operator KEK) with
// AAD binding on both layers — callers must pass the same aad on Decrypt.
// Legacy v0 (single-layer, no AAD) still accepted on Decrypt for blobs
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	formatVersionV1 = 0x01
	nonceSize       = 12
	tagSize         = 16
	dekSize         = 32
	wrappedDEKSize  = nonceSize + dekSize + tagSize // 60
	v1MinSize       = 1 + wrappedDEKSize + nonceSize + tagSize
)

func Encrypt(plaintext, kek, aad []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("invalid KEK length: want 32 bytes, got %d", len(kek))
	}

	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}

	wrappedDEK, err := sealAESGCM(dek, kek, aad)
	if err != nil {
		return nil, fmt.Errorf("wrap DEK: %w", err)
	}
	sealedData, err := sealAESGCM(plaintext, dek, aad)
	if err != nil {
		return nil, fmt.Errorf("seal data: %w", err)
	}

	out := make([]byte, 0, 1+len(wrappedDEK)+len(sealedData))
	out = append(out, formatVersionV1)
	out = append(out, wrappedDEK...)
	out = append(out, sealedData...)
	return out, nil
}

func Decrypt(ciphertext, kek, aad []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("invalid KEK length: want 32 bytes, got %d", len(kek))
	}

	if pt, err := decryptV1(ciphertext, kek, aad); err == nil {
		return pt, nil
	}
	pt, err := decryptLegacy(ciphertext, kek)
	if err != nil {
		return nil, errors.New("decryption failed (wrong key, tampered data, or AAD mismatch)")
	}
	return pt, nil
}

func decryptV1(ciphertext, kek, aad []byte) ([]byte, error) {
	if len(ciphertext) < v1MinSize || ciphertext[0] != formatVersionV1 {
		return nil, errors.New("not v1")
	}
	wrappedDEK := ciphertext[1 : 1+wrappedDEKSize]
	sealedData := ciphertext[1+wrappedDEKSize:]

	dek, err := openAESGCM(wrappedDEK, kek, aad)
	if err != nil {
		return nil, fmt.Errorf("unwrap DEK: %w", err)
	}
	return openAESGCM(sealedData, dek, aad)
}

func decryptLegacy(ciphertext, kek []byte) ([]byte, error) {
	return openAESGCM(ciphertext, kek, nil)
}

func sealAESGCM(plaintext, key, aad []byte) ([]byte, error) {
	aesGCM, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return aesGCM.Seal(nonce, nonce, plaintext, aad), nil
}

func openAESGCM(blob, key, aad []byte) ([]byte, error) {
	aesGCM, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < aesGCM.NonceSize()+tagSize {
		return nil, errors.New("blob too short")
	}
	nonce, body := blob[:aesGCM.NonceSize()], blob[aesGCM.NonceSize():]
	return aesGCM.Open(nil, nonce, body, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	return cipher.NewGCM(block)
}
