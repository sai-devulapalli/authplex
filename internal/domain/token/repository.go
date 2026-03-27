package token

import (
	"context"
	"time"
)

// CodeRepository stores and retrieves authorization codes.
// Implementation uses Redis with TTL for automatic expiry.
type CodeRepository interface {
	Store(ctx context.Context, code AuthorizationCode) error
	Consume(ctx context.Context, code string) (AuthorizationCode, error) // get + delete atomically
}

// RefreshTokenRepository stores and manages refresh tokens.
type RefreshTokenRepository interface {
	Store(ctx context.Context, rt RefreshToken) error
	GetByToken(ctx context.Context, token string) (RefreshToken, error)
	RevokeByToken(ctx context.Context, token string) error
	RevokeFamily(ctx context.Context, familyID string) error
}

// DeviceCodeRepository stores and manages device authorization codes.
type DeviceCodeRepository interface {
	Store(ctx context.Context, dc DeviceCode) error
	GetByDeviceCode(ctx context.Context, deviceCode string) (DeviceCode, error)
	GetByUserCode(ctx context.Context, userCode string) (DeviceCode, error)
	Authorize(ctx context.Context, userCode string, subject string) error
	Deny(ctx context.Context, userCode string) error
}

// TokenBlacklist tracks revoked tokens by JTI.
type TokenBlacklist interface {
	Revoke(ctx context.Context, jti string, expiresAt time.Time) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
}
