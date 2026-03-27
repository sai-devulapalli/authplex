package errors

import (
	"errors"
	"fmt"
)

// AppError is a structured, classifiable error. It carries an error code,
// human-readable message, optional cause, and arbitrary details.
// All application-layer errors should use AppError instead of panic.
type AppError struct {
	Code    ErrorCode      `json:"code"`
	Message string         `json:"message"`
	Cause   error          `json:"-"`
	Details map[string]any `json:"details,omitempty"`
}

// Error implements the error interface.
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause for errors.Is/As chain traversal.
func (e *AppError) Unwrap() error {
	return e.Cause
}

// New creates a new AppError with the given code and message.
func New(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
	}
}

// Wrap creates an AppError wrapping an existing error.
func Wrap(code ErrorCode, message string, cause error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// WithDetails returns a copy of the AppError with additional details.
func (e *AppError) WithDetails(details map[string]any) *AppError {
	return &AppError{
		Code:    e.Code,
		Message: e.Message,
		Cause:   e.Cause,
		Details: details,
	}
}

// Is checks whether the target error is an AppError with the same code.
func Is(err error, code ErrorCode) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == code
	}
	return false
}
