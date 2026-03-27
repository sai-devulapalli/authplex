package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBcryptHasher_HashAndVerify(t *testing.T) {
	hasher := NewBcryptHasher()

	hash, err := hasher.Hash("my-secret-123")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	err = hasher.Verify("my-secret-123", hash)
	assert.NoError(t, err)
}

func TestBcryptHasher_VerifyWrongSecret(t *testing.T) {
	hasher := NewBcryptHasher()

	hash, err := hasher.Hash("correct-secret")
	require.NoError(t, err)

	err = hasher.Verify("wrong-secret", hash)
	assert.Error(t, err)
}

func TestBcryptHasher_DifferentHashesForSameInput(t *testing.T) {
	hasher := NewBcryptHasher()

	hash1, err := hasher.Hash("secret")
	require.NoError(t, err)
	hash2, err := hasher.Hash("secret")
	require.NoError(t, err)

	// bcrypt generates different hashes due to random salt
	assert.NotEqual(t, hash1, hash2)

	// Both should verify
	assert.NoError(t, hasher.Verify("secret", hash1))
	assert.NoError(t, hasher.Verify("secret", hash2))
}
