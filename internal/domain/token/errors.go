package token

// CodeExpiredError indicates the authorization code has expired.
type CodeExpiredError struct{}

func (e *CodeExpiredError) Error() string {
	return "authorization code has expired"
}

// CodeNotFoundError indicates the authorization code was not found.
type CodeNotFoundError struct{}

func (e *CodeNotFoundError) Error() string {
	return "authorization code not found"
}

// InvalidGrantError indicates the token request is invalid.
type InvalidGrantError struct {
	Reason string
}

func (e *InvalidGrantError) Error() string {
	return "invalid grant: " + e.Reason
}
