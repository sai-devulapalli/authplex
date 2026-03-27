package mfa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMFAPolicy_IsRequired(t *testing.T) {
	assert.True(t, MFAPolicy{Required: MFARequired}.IsRequired())
	assert.False(t, MFAPolicy{Required: MFAOptional}.IsRequired())
	assert.False(t, MFAPolicy{Required: MFANone}.IsRequired())
}

func TestMFAPolicy_HasMethod(t *testing.T) {
	p := MFAPolicy{Methods: []string{"totp", "webauthn"}}

	assert.True(t, p.HasMethod("totp"))
	assert.True(t, p.HasMethod("webauthn"))
	assert.False(t, p.HasMethod("sms"))
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Field: "code", Message: "is invalid"}
	assert.Equal(t, "mfa validation: code is invalid", err.Error())
}
