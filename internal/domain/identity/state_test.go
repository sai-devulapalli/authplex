package identity

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOAuthState_IsExpired(t *testing.T) {
	expired := OAuthState{ExpiresAt: time.Now().UTC().Add(-1 * time.Minute)}
	assert.True(t, expired.IsExpired())

	valid := OAuthState{ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}
	assert.False(t, valid.IsExpired())
}
