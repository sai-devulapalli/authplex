package mfa

import "fmt"

// ValidationError is returned when an MFA field fails validation.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("mfa validation: %s %s", e.Field, e.Message)
}
