package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDeviceCode_IsExpiredDevice(t *testing.T) {
	dc := DeviceCode{ExpiresAt: time.Now().UTC().Add(-1 * time.Minute)}
	assert.True(t, dc.IsExpiredDevice())

	dc2 := DeviceCode{ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}
	assert.False(t, dc2.IsExpiredDevice())
}

func TestDeviceCode_IsPending(t *testing.T) {
	dc := DeviceCode{}
	assert.True(t, dc.IsPending())

	dc.Authorized = true
	assert.False(t, dc.IsPending())

	dc2 := DeviceCode{Denied: true}
	assert.False(t, dc2.IsPending())
}
