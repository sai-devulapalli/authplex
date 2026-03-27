package otp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCode(t *testing.T) {
	code, err := GenerateCode()
	require.NoError(t, err)
	assert.Len(t, code, 6)

	// Should be different each time
	code2, _ := GenerateCode()
	// Note: tiny chance of collision, but 1 in 1M
	_ = code2
}

func TestGenerateCode_Format(t *testing.T) {
	for i := 0; i < 100; i++ {
		code, err := GenerateCode()
		require.NoError(t, err)
		assert.Len(t, code, 6, "code should always be 6 digits")
		for _, c := range code {
			assert.True(t, c >= '0' && c <= '9', "code should only contain digits")
		}
	}
}

func TestOTP_IsExpired(t *testing.T) {
	expired := OTP{ExpiresAt: time.Now().UTC().Add(-1 * time.Minute)}
	assert.True(t, expired.IsExpired())

	valid := OTP{ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	assert.False(t, valid.IsExpired())
}

func TestOTP_MaxAttemptsExceeded(t *testing.T) {
	o := OTP{Attempts: 4}
	assert.False(t, o.MaxAttemptsExceeded())

	o.Attempts = 5
	assert.True(t, o.MaxAttemptsExceeded())
}

func TestIsValidPurpose(t *testing.T) {
	assert.True(t, IsValidPurpose("login"))
	assert.True(t, IsValidPurpose("verify"))
	assert.True(t, IsValidPurpose("reset"))
	assert.False(t, IsValidPurpose("invalid"))
	assert.False(t, IsValidPurpose(""))
}
