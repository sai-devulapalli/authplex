package mfa

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMFAChallenge_IsExpired(t *testing.T) {
	expired := MFAChallenge{ExpiresAt: time.Now().UTC().Add(-1 * time.Minute)}
	assert.True(t, expired.IsExpired())

	valid := MFAChallenge{ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	assert.False(t, valid.IsExpired())
}
