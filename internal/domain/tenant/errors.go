package tenant

import "fmt"

// ValidationError is returned when a tenant field fails validation.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("tenant validation: %s %s", e.Field, e.Message)
}
