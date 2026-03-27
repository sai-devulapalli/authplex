package mfa

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/authcore/internal/application/auth"
	"github.com/authcore/internal/application/jwks"
	domainmfa "github.com/authcore/internal/domain/mfa"
	"github.com/authcore/internal/domain/jwk"
	"github.com/authcore/internal/domain/token"
	apperrors "github.com/authcore/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---

type mockTOTPRepo struct {
	enrollments map[string]domainmfa.TOTPEnrollment
}

func newMockTOTPRepo() *mockTOTPRepo {
	return &mockTOTPRepo{enrollments: make(map[string]domainmfa.TOTPEnrollment)}
}

func (m *mockTOTPRepo) Store(_ context.Context, e domainmfa.TOTPEnrollment) error {
	m.enrollments[e.ID] = e
	return nil
}
func (m *mockTOTPRepo) GetBySubject(_ context.Context, tenantID, subject string) (domainmfa.TOTPEnrollment, error) {
	for _, e := range m.enrollments {
		if e.TenantID == tenantID && e.Subject == subject {
			return e, nil
		}
	}
	return domainmfa.TOTPEnrollment{}, errors.New("not found")
}
func (m *mockTOTPRepo) Confirm(_ context.Context, id string) error {
	e, ok := m.enrollments[id]
	if !ok {
		return errors.New("not found")
	}
	e.Confirmed = true
	m.enrollments[id] = e
	return nil
}
func (m *mockTOTPRepo) Delete(_ context.Context, id string) error {
	delete(m.enrollments, id)
	return nil
}

type mockChallengeRepo struct {
	challenges map[string]domainmfa.MFAChallenge
}

func newMockChallengeRepo() *mockChallengeRepo {
	return &mockChallengeRepo{challenges: make(map[string]domainmfa.MFAChallenge)}
}

func (m *mockChallengeRepo) Store(_ context.Context, c domainmfa.MFAChallenge) error {
	m.challenges[c.ID] = c
	return nil
}
func (m *mockChallengeRepo) GetByID(_ context.Context, id string) (domainmfa.MFAChallenge, error) {
	c, ok := m.challenges[id]
	if !ok {
		return domainmfa.MFAChallenge{}, errors.New("not found")
	}
	return c, nil
}
func (m *mockChallengeRepo) MarkVerified(_ context.Context, id string) error {
	c := m.challenges[id]
	c.Verified = true
	m.challenges[id] = c
	return nil
}
func (m *mockChallengeRepo) Delete(_ context.Context, id string) error {
	delete(m.challenges, id)
	return nil
}

type mockJWKRepo struct{}
func (m *mockJWKRepo) Store(_ context.Context, _ jwk.KeyPair) error { return nil }
func (m *mockJWKRepo) GetActive(_ context.Context, _ string) (jwk.KeyPair, error) {
	return jwk.KeyPair{ID: "kid", Algorithm: "RS256", PrivateKey: []byte("key")}, nil
}
func (m *mockJWKRepo) GetAllPublic(_ context.Context, _ string) ([]jwk.KeyPair, error) { return nil, nil }
func (m *mockJWKRepo) Deactivate(_ context.Context, _ string) error { return nil }

type mockGen struct{}
func (m *mockGen) GenerateRSA() ([]byte, []byte, error) { return nil, nil, nil }
func (m *mockGen) GenerateEC() ([]byte, []byte, error) { return nil, nil, nil }

type mockConv struct{}
func (m *mockConv) PEMToPublicJWK(_ []byte, _ string, _ string) (jwk.PublicJWK, error) { return jwk.PublicJWK{}, nil }

type mockCodeRepo struct{}
func (m *mockCodeRepo) Store(_ context.Context, _ token.AuthorizationCode) error { return nil }
func (m *mockCodeRepo) Consume(_ context.Context, _ string) (token.AuthorizationCode, error) {
	return token.AuthorizationCode{}, errors.New("not found")
}

type mockSigner struct{}
func (m *mockSigner) Sign(_ token.Claims, _ string, _ []byte, _ string) (string, error) {
	return "mock-jwt", nil
}

func newTestAuthSvc() *auth.Service {
	jwksSvc := jwks.NewService(&mockJWKRepo{}, &mockGen{}, &mockConv{}, slog.Default())
	return auth.NewService(&mockCodeRepo{}, jwksSvc, &mockSigner{}, slog.Default())
}

// --- Tests ---

func TestEnrollTOTP_Success(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	resp, appErr := svc.EnrollTOTP(context.Background(), EnrollRequest{
		Subject: "user-1", TenantID: "t1",
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.Secret)
	assert.Contains(t, resp.OTPAuthURI, "otpauth://totp/")
	assert.Contains(t, resp.OTPAuthURI, "user-1")
}

func TestEnrollTOTP_AlreadyEnrolled(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Confirmed: true,
	}
	svc := NewService(totpRepo, newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	_, appErr := svc.EnrollTOTP(context.Background(), EnrollRequest{
		Subject: "user-1", TenantID: "t1",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrConflict, appErr.Code)
}

func TestEnrollTOTP_MissingSubject(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	_, appErr := svc.EnrollTOTP(context.Background(), EnrollRequest{TenantID: "t1"})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestConfirmTOTP_Success(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	secret := []byte("12345678901234567890")
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Secret: secret, Confirmed: false,
	}

	svc := NewService(totpRepo, newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	code := domainmfa.GenerateTOTP(secret, time.Now().UTC())
	appErr := svc.ConfirmTOTP(context.Background(), VerifyRequest{
		Subject: "user-1", TenantID: "t1", Code: code,
	})

	assert.Nil(t, appErr)
	assert.True(t, totpRepo.enrollments["e1"].Confirmed)
}

func TestConfirmTOTP_WrongCode(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Secret: []byte("secret"), Confirmed: false,
	}

	svc := NewService(totpRepo, newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	appErr := svc.ConfirmTOTP(context.Background(), VerifyRequest{
		Subject: "user-1", TenantID: "t1", Code: "000000",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestConfirmTOTP_NotEnrolled(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	appErr := svc.ConfirmTOTP(context.Background(), VerifyRequest{
		Subject: "user-1", TenantID: "t1", Code: "123456",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestConfirmTOTP_AlreadyConfirmed(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Secret: []byte("s"), Confirmed: true,
	}

	svc := NewService(totpRepo, newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	appErr := svc.ConfirmTOTP(context.Background(), VerifyRequest{
		Subject: "user-1", TenantID: "t1", Code: "123456",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrConflict, appErr.Code)
}

func TestVerifyMFA_Success(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	secret := []byte("12345678901234567890")
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Secret: secret, Confirmed: true,
	}

	challengeRepo := newMockChallengeRepo()
	challengeRepo.challenges["ch1"] = domainmfa.MFAChallenge{
		ID:                  "ch1",
		Subject:             "user-1",
		TenantID:            "t1",
		ExpiresAt:           time.Now().UTC().Add(5 * time.Minute),
		OriginalClientID:    "client-1",
		OriginalRedirectURI: "https://example.com/cb",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}

	svc := NewService(totpRepo, challengeRepo, newTestAuthSvc(), slog.Default())

	code := domainmfa.GenerateTOTP(secret, time.Now().UTC())
	resp, appErr := svc.VerifyMFA(context.Background(), MFAVerifyRequest{
		ChallengeID: "ch1", Method: "totp", Code: code,
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.Code)
}

func TestVerifyMFA_ChallengeNotFound(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	_, appErr := svc.VerifyMFA(context.Background(), MFAVerifyRequest{
		ChallengeID: "nonexistent", Code: "123456",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestVerifyMFA_ChallengeExpired(t *testing.T) {
	challengeRepo := newMockChallengeRepo()
	challengeRepo.challenges["ch1"] = domainmfa.MFAChallenge{
		ID:        "ch1",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Minute),
	}

	svc := NewService(newMockTOTPRepo(), challengeRepo, newTestAuthSvc(), slog.Default())

	_, appErr := svc.VerifyMFA(context.Background(), MFAVerifyRequest{
		ChallengeID: "ch1", Code: "123456",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrExpiredCode, appErr.Code)
}

func TestVerifyMFA_WrongCode(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Secret: []byte("secret"), Confirmed: true,
	}

	challengeRepo := newMockChallengeRepo()
	challengeRepo.challenges["ch1"] = domainmfa.MFAChallenge{
		ID: "ch1", Subject: "user-1", TenantID: "t1",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	}

	svc := NewService(totpRepo, challengeRepo, newTestAuthSvc(), slog.Default())

	_, appErr := svc.VerifyMFA(context.Background(), MFAVerifyRequest{
		ChallengeID: "ch1", Code: "000000",
	})

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}

func TestCreateChallenge(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	resp, appErr := svc.CreateChallenge(context.Background(), CreateChallengeRequest{
		Subject:  "user-1",
		TenantID: "t1",
		Methods:  []string{"totp"},
	})

	require.Nil(t, appErr)
	assert.NotEmpty(t, resp.ChallengeID)
	assert.True(t, resp.MFARequired)
	assert.Contains(t, resp.Methods, "totp")
	assert.Greater(t, resp.ExpiresIn, 0)
}

func TestHasEnrolledMFA_True(t *testing.T) {
	totpRepo := newMockTOTPRepo()
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "t1", Confirmed: true,
	}

	svc := NewService(totpRepo, newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	assert.True(t, svc.HasEnrolledMFA(context.Background(), "t1", "user-1"))
}

func TestHasEnrolledMFA_False(t *testing.T) {
	svc := NewService(newMockTOTPRepo(), newMockChallengeRepo(), newTestAuthSvc(), slog.Default())

	assert.False(t, svc.HasEnrolledMFA(context.Background(), "t1", "nonexistent"))
}
