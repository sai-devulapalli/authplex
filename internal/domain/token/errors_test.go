package token

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCodeExpiredError(t *testing.T) {
	err := &CodeExpiredError{}
	assert.Equal(t, "authorization code has expired", err.Error())
}

func TestCodeNotFoundError(t *testing.T) {
	err := &CodeNotFoundError{}
	assert.Equal(t, "authorization code not found", err.Error())
}

func TestInvalidGrantError(t *testing.T) {
	err := &InvalidGrantError{Reason: "client_id mismatch"}
	assert.Equal(t, "invalid grant: client_id mismatch", err.Error())
}
