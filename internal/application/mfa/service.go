package mfa

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"log/slog"
	"time"

	"github.com/authcore/internal/application/auth"
	domainmfa "github.com/authcore/internal/domain/mfa"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// Service provides MFA operations.
type Service struct {
	totpRepo      domainmfa.TOTPRepository
	challengeRepo domainmfa.ChallengeRepository
	authSvc       *auth.Service
	logger        *slog.Logger
	challengeTTL  time.Duration
}

// NewService creates a new MFA service.
func NewService(
	totpRepo domainmfa.TOTPRepository,
	challengeRepo domainmfa.ChallengeRepository,
	authSvc *auth.Service,
	logger *slog.Logger,
) *Service {
	return &Service{
		totpRepo:      totpRepo,
		challengeRepo: challengeRepo,
		authSvc:       authSvc,
		logger:        logger,
		challengeTTL:  5 * time.Minute,
	}
}

// EnrollTOTP generates a new TOTP secret for the user.
func (s *Service) EnrollTOTP(ctx context.Context, req EnrollRequest) (EnrollResponse, *apperrors.AppError) {
	if req.Subject == "" {
		return EnrollResponse{}, apperrors.New(apperrors.ErrBadRequest, "subject is required")
	}

	// Check if already enrolled
	existing, err := s.totpRepo.GetBySubject(ctx, req.TenantID, req.Subject)
	if err == nil && existing.Confirmed {
		return EnrollResponse{}, apperrors.New(apperrors.ErrConflict, "TOTP already enrolled")
	}

	// Generate secret
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return EnrollResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate secret", err)
	}

	id, err := generateID()
	if err != nil {
		return EnrollResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate ID", err)
	}

	enrollment := domainmfa.TOTPEnrollment{
		ID:        id,
		Subject:   req.Subject,
		TenantID:  req.TenantID,
		Secret:    secret,
		Confirmed: false,
		CreatedAt: time.Now().UTC(),
	}

	if storeErr := s.totpRepo.Store(ctx, enrollment); storeErr != nil {
		return EnrollResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to store enrollment", storeErr)
	}

	encodedSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	otpauthURI := domainmfa.BuildOTPAuthURI("AuthCore", req.Subject, encodedSecret)

	s.logger.Info("TOTP enrollment initiated", "subject", req.Subject, "tenant_id", req.TenantID)

	return EnrollResponse{
		Secret:     encodedSecret,
		OTPAuthURI: otpauthURI,
	}, nil
}

// ConfirmTOTP confirms enrollment after the user verifies their first code.
func (s *Service) ConfirmTOTP(ctx context.Context, req VerifyRequest) *apperrors.AppError {
	enrollment, err := s.totpRepo.GetBySubject(ctx, req.TenantID, req.Subject)
	if err != nil {
		return apperrors.New(apperrors.ErrNotFound, "no pending TOTP enrollment")
	}
	if enrollment.Confirmed {
		return apperrors.New(apperrors.ErrConflict, "TOTP already confirmed")
	}

	if !domainmfa.VerifyTOTP(enrollment.Secret, req.Code, time.Now().UTC()) {
		return apperrors.New(apperrors.ErrBadRequest, "invalid TOTP code")
	}

	if confirmErr := s.totpRepo.Confirm(ctx, enrollment.ID); confirmErr != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to confirm enrollment", confirmErr)
	}

	s.logger.Info("TOTP enrollment confirmed", "subject", req.Subject)
	return nil
}

// VerifyMFA verifies a TOTP code against an MFA challenge and completes the auth flow.
func (s *Service) VerifyMFA(ctx context.Context, req MFAVerifyRequest) (auth.AuthorizeResponse, *apperrors.AppError) {
	challenge, err := s.challengeRepo.GetByID(ctx, req.ChallengeID)
	if err != nil {
		return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrNotFound, "challenge not found")
	}
	if challenge.IsExpired() {
		return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrExpiredCode, "MFA challenge has expired")
	}
	if challenge.Verified {
		return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrBadRequest, "challenge already verified")
	}

	// Verify the TOTP code
	enrollment, getErr := s.totpRepo.GetBySubject(ctx, challenge.TenantID, challenge.Subject)
	if getErr != nil {
		return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrBadRequest, "TOTP not enrolled")
	}
	if !enrollment.Confirmed {
		return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrBadRequest, "TOTP not confirmed")
	}

	if !domainmfa.VerifyTOTP(enrollment.Secret, req.Code, time.Now().UTC()) {
		return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrBadRequest, "invalid TOTP code")
	}

	// Mark challenge as verified
	s.challengeRepo.MarkVerified(ctx, req.ChallengeID) //nolint:errcheck

	// Complete the original authorize flow
	authReq := auth.AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            challenge.OriginalClientID,
		RedirectURI:         challenge.OriginalRedirectURI,
		Scope:               challenge.OriginalScope,
		State:               challenge.OriginalState,
		CodeChallenge:       challenge.CodeChallenge,
		CodeChallengeMethod: challenge.CodeChallengeMethod,
		Subject:             challenge.Subject,
		TenantID:            challenge.TenantID,
		Nonce:               challenge.Nonce,
	}

	resp, authErr := s.authSvc.Authorize(ctx, authReq)
	if authErr != nil {
		return auth.AuthorizeResponse{}, authErr
	}

	// Clean up challenge
	s.challengeRepo.Delete(ctx, req.ChallengeID) //nolint:errcheck

	s.logger.Info("MFA verified, auth code issued", "subject", challenge.Subject)
	return resp, nil
}

// CreateChallenge creates an MFA challenge for the authorize flow.
func (s *Service) CreateChallenge(ctx context.Context, req CreateChallengeRequest) (ChallengeResponse, *apperrors.AppError) {
	id, err := generateID()
	if err != nil {
		return ChallengeResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate challenge ID", err)
	}

	challenge := domainmfa.MFAChallenge{
		ID:                  id,
		Subject:             req.Subject,
		TenantID:            req.TenantID,
		Methods:             req.Methods,
		ExpiresAt:           time.Now().UTC().Add(s.challengeTTL),
		OriginalClientID:    req.OriginalClientID,
		OriginalRedirectURI: req.OriginalRedirectURI,
		OriginalScope:       req.OriginalScope,
		OriginalState:       req.OriginalState,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
	}

	if storeErr := s.challengeRepo.Store(ctx, challenge); storeErr != nil {
		return ChallengeResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to store challenge", storeErr)
	}

	return ChallengeResponse{
		MFARequired: true,
		ChallengeID: id,
		Methods:     req.Methods,
		ExpiresIn:   int(s.challengeTTL.Seconds()),
	}, nil
}

// HasEnrolledMFA checks if a user has a confirmed TOTP enrollment.
func (s *Service) HasEnrolledMFA(ctx context.Context, tenantID, subject string) bool {
	enrollment, err := s.totpRepo.GetBySubject(ctx, tenantID, subject)
	if err != nil {
		return false
	}
	return enrollment.Confirmed
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
