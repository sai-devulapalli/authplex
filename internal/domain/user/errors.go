package user

import "fmt"

// ValidationError is returned when a user field fails validation.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("user validation: %s %s", e.Field, e.Message)
}
