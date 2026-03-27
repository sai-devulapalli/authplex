package jwk

import "fmt"

// ValidationError is returned when a JWK field fails validation.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("jwk validation: %s %s", e.Field, e.Message)
}
