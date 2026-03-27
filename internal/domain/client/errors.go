package client

import "fmt"

// ValidationError is returned when a client field fails validation.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("client validation: %s %s", e.Field, e.Message)
}
