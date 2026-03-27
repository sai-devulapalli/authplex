package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorCode_HTTPStatus(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		expected int
	}{
		{ErrNotFound, 404},
		{ErrUnauthorized, 401},
		{ErrBadRequest, 400},
		{ErrInternal, 500},
		{ErrConflict, 409},
		{ErrForbidden, 403},
		{ErrTokenExpired, 401},
		{ErrTokenInvalid, 401},
		{ErrPKCEFailed, 400},
		{ErrInvalidClient, 401},
		{ErrUnsupportedGrant, 400},
		{ErrSlowDown, 400},
		{ErrAuthorizationPending, 400},
		{ErrExpiredCode, 400},
		{ErrAccessDenied, 403},
		{ErrMFARequired, 403},
		{ErrorCode("UNKNOWN"), 500},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.code.HTTPStatus())
		})
	}
}
