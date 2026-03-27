package errors

// ErrorCode classifies application errors for consistent handling across layers.
type ErrorCode string

const (
	ErrNotFound     ErrorCode = "NOT_FOUND"
	ErrUnauthorized ErrorCode = "UNAUTHORIZED"
	ErrBadRequest   ErrorCode = "BAD_REQUEST"
	ErrInternal     ErrorCode = "INTERNAL"
	ErrConflict     ErrorCode = "CONFLICT"
	ErrForbidden    ErrorCode = "FORBIDDEN"
	ErrTokenExpired ErrorCode = "TOKEN_EXPIRED"
	ErrTokenInvalid ErrorCode = "TOKEN_INVALID"
	ErrPKCEFailed           ErrorCode = "PKCE_VERIFICATION_FAILED"
	ErrInvalidClient        ErrorCode = "INVALID_CLIENT"
	ErrUnsupportedGrant     ErrorCode = "UNSUPPORTED_GRANT"
	ErrSlowDown             ErrorCode = "SLOW_DOWN"
	ErrAuthorizationPending ErrorCode = "AUTHORIZATION_PENDING"
	ErrExpiredCode          ErrorCode = "EXPIRED_CODE"
	ErrAccessDenied         ErrorCode = "ACCESS_DENIED"
	ErrMFARequired          ErrorCode = "MFA_REQUIRED"
)

// HTTPStatus maps an ErrorCode to its corresponding HTTP status code.
func (c ErrorCode) HTTPStatus() int {
	switch c {
	case ErrNotFound:
		return 404
	case ErrUnauthorized:
		return 401
	case ErrBadRequest:
		return 400
	case ErrInternal:
		return 500
	case ErrConflict:
		return 409
	case ErrForbidden:
		return 403
	case ErrTokenExpired:
		return 401
	case ErrTokenInvalid:
		return 401
	case ErrPKCEFailed:
		return 400
	case ErrInvalidClient:
		return 401
	case ErrUnsupportedGrant:
		return 400
	case ErrSlowDown:
		return 400
	case ErrAuthorizationPending:
		return 400
	case ErrExpiredCode:
		return 400
	case ErrAccessDenied:
		return 403
	case ErrMFARequired:
		return 403
	default:
		return 500
	}
}
