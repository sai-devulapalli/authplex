package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// Encryptor provides AES-256-GCM encryption for data at rest.
type Encryptor struct {
	gcm cipher.AEAD
}

// NewEncryptor creates a new Encryptor from a hex-encoded 32-byte key.
// If key is empty, returns nil (no encryption — development mode).
func NewEncryptor(hexKey string) (*Encryptor, error) {
	if hexKey == "" {
		return nil, nil
	}

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &Encryptor{gcm: gcm}, nil
}

// Encrypt encrypts plaintext and returns ciphertext (nonce prepended).
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return e.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext (nonce prepended) and returns plaintext.
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := e.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return e.gcm.Open(nil, nonce, ciphertext, nil)
}

// EncryptIfConfigured encrypts data if an encryptor is available, otherwise returns data as-is.
func EncryptIfConfigured(enc *Encryptor, data []byte) ([]byte, error) {
	if enc == nil {
		return data, nil
	}
	return enc.Encrypt(data)
}

// DecryptIfConfigured decrypts data if an encryptor is available, otherwise returns data as-is.
func DecryptIfConfigured(enc *Encryptor, data []byte) ([]byte, error) {
	if enc == nil {
		return data, nil
	}
	return enc.Decrypt(data)
}
