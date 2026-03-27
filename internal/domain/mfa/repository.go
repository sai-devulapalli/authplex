package mfa

import "context"

// TOTPRepository is the port interface for TOTP enrollment persistence.
type TOTPRepository interface {
	Store(ctx context.Context, enrollment TOTPEnrollment) error
	GetBySubject(ctx context.Context, tenantID, subject string) (TOTPEnrollment, error)
	Confirm(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}

// ChallengeRepository is the port interface for MFA challenge persistence.
type ChallengeRepository interface {
	Store(ctx context.Context, challenge MFAChallenge) error
	GetByID(ctx context.Context, id string) (MFAChallenge, error)
	MarkVerified(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}
