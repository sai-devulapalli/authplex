package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey() string {
	// 32 bytes = 64 hex chars
	return hex.EncodeToString([]byte("01234567890123456789012345678901"))
}

func TestEncryptor_EncryptDecrypt(t *testing.T) {
	enc, err := NewEncryptor(testKey())
	require.NoError(t, err)

	plaintext := []byte("super-secret-totp-key")
	ciphertext, err := enc.Encrypt(plaintext)
	require.NoError(t, err)

	assert.NotEqual(t, plaintext, ciphertext)
	assert.Greater(t, len(ciphertext), len(plaintext))

	decrypted, err := enc.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptor_DifferentCiphertexts(t *testing.T) {
	enc, _ := NewEncryptor(testKey())

	ct1, _ := enc.Encrypt([]byte("data"))
	ct2, _ := enc.Encrypt([]byte("data"))

	// Same plaintext → different ciphertext (random nonce)
	assert.NotEqual(t, ct1, ct2)
}

func TestEncryptor_EmptyKey_ReturnsNil(t *testing.T) {
	enc, err := NewEncryptor("")
	assert.NoError(t, err)
	assert.Nil(t, enc)
}

func TestEncryptor_InvalidKey(t *testing.T) {
	_, err := NewEncryptor("not-hex")
	assert.Error(t, err)
}

func TestEncryptor_WrongKeyLength(t *testing.T) {
	_, err := NewEncryptor(hex.EncodeToString([]byte("short")))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestEncryptor_DecryptCorrupted(t *testing.T) {
	enc, _ := NewEncryptor(testKey())

	_, err := enc.Decrypt([]byte("too-short"))
	assert.Error(t, err)
}

func TestEncryptIfConfigured_WithEncryptor(t *testing.T) {
	enc, _ := NewEncryptor(testKey())

	ct, err := EncryptIfConfigured(enc, []byte("data"))
	require.NoError(t, err)
	assert.NotEqual(t, []byte("data"), ct)

	pt, err := DecryptIfConfigured(enc, ct)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), pt)
}

func TestEncryptIfConfigured_NilEncryptor(t *testing.T) {
	ct, err := EncryptIfConfigured(nil, []byte("data"))
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), ct)

	pt, err := DecryptIfConfigured(nil, ct)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), pt)
}
