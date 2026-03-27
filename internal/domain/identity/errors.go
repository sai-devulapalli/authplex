package identity

import "fmt"

// ValidationError is returned when an identity field fails validation.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("identity validation: %s %s", e.Field, e.Message)
}
