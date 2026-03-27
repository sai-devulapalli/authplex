package errors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	err := New(ErrNotFound, "user not found")

	assert.Equal(t, ErrNotFound, err.Code)
	assert.Equal(t, "user not found", err.Message)
	assert.Nil(t, err.Cause)
	assert.Nil(t, err.Details)
}

func TestWrap(t *testing.T) {
	cause := fmt.Errorf("connection refused")
	err := Wrap(ErrInternal, "database error", cause)

	assert.Equal(t, ErrInternal, err.Code)
	assert.Equal(t, "database error", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *AppError
		expected string
	}{
		{
			name:     "without cause",
			err:      New(ErrNotFound, "not found"),
			expected: "NOT_FOUND: not found",
		},
		{
			name:     "with cause",
			err:      Wrap(ErrInternal, "db error", fmt.Errorf("timeout")),
			expected: "INTERNAL: db error: timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestAppError_Unwrap(t *testing.T) {
	cause := fmt.Errorf("root cause")
	err := Wrap(ErrInternal, "wrapped", cause)

	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestAppError_Unwrap_NilCause(t *testing.T) {
	err := New(ErrNotFound, "not found")
	assert.Nil(t, err.Unwrap())
}

func TestAppError_WithDetails(t *testing.T) {
	original := New(ErrBadRequest, "validation failed")
	details := map[string]any{"field": "email", "reason": "invalid format"}

	withDetails := original.WithDetails(details)

	// Original unchanged
	assert.Nil(t, original.Details)

	// New error has details
	assert.Equal(t, details, withDetails.Details)
	assert.Equal(t, original.Code, withDetails.Code)
	assert.Equal(t, original.Message, withDetails.Message)
}

func TestIs(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		code     ErrorCode
		expected bool
	}{
		{
			name:     "matching code",
			err:      New(ErrNotFound, "not found"),
			code:     ErrNotFound,
			expected: true,
		},
		{
			name:     "non-matching code",
			err:      New(ErrNotFound, "not found"),
			code:     ErrInternal,
			expected: false,
		},
		{
			name:     "non-AppError",
			err:      fmt.Errorf("plain error"),
			code:     ErrInternal,
			expected: false,
		},
		{
			name:     "wrapped AppError",
			err:      fmt.Errorf("outer: %w", New(ErrUnauthorized, "no token")),
			code:     ErrUnauthorized,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Is(tt.err, tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAppError_ErrorsAs(t *testing.T) {
	err := Wrap(ErrInternal, "db failure", fmt.Errorf("connection lost"))
	wrapped := fmt.Errorf("service error: %w", err)

	var appErr *AppError
	require.True(t, errors.As(wrapped, &appErr))
	assert.Equal(t, ErrInternal, appErr.Code)
}
