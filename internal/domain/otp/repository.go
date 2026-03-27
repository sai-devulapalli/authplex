package otp

import "context"

// Repository is the port interface for OTP storage.
type Repository interface {
	Store(ctx context.Context, o OTP) error
	Get(ctx context.Context, identifier, tenantID string) (OTP, error)
	IncrementAttempts(ctx context.Context, identifier, tenantID string) error
	Delete(ctx context.Context, identifier, tenantID string) error
}

// EmailSender is the port interface for sending OTP via email.
type EmailSender interface {
	SendOTP(ctx context.Context, to, code string) error
}

// SMSSender is the port interface for sending OTP via SMS.
type SMSSender interface {
	SendOTP(ctx context.Context, phone, code string) error
}
