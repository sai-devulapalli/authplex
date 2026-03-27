package otp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

// Channel represents the delivery channel for an OTP.
type Channel string

const (
	ChannelEmail Channel = "email"
	ChannelSMS   Channel = "sms"
)

// Purpose represents why the OTP was requested.
type Purpose string

const (
	PurposeLogin  Purpose = "login"
	PurposeVerify Purpose = "verify"
	PurposeReset  Purpose = "reset"
)

// OTP represents a one-time password sent to a user.
type OTP struct {
	Identifier string
	Code       string
	Channel    Channel
	Purpose    Purpose
	TenantID   string
	ExpiresAt  time.Time
	Attempts   int
}

// IsExpired returns true if the OTP has passed its TTL.
func (o OTP) IsExpired() bool {
	return time.Now().UTC().After(o.ExpiresAt)
}

// MaxAttemptsExceeded returns true if too many failed verifications.
func (o OTP) MaxAttemptsExceeded() bool {
	return o.Attempts >= 5
}

// GenerateCode creates a cryptographically random 6-digit OTP code.
func GenerateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", fmt.Errorf("failed to generate OTP: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// IsValidPurpose checks if a purpose string is valid.
func IsValidPurpose(p string) bool {
	switch Purpose(p) {
	case PurposeLogin, PurposeVerify, PurposeReset:
		return true
	default:
		return false
	}
}
