package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authcore/internal/application/auth"
	"github.com/authcore/internal/application/jwks"
	mfasvc "github.com/authcore/internal/application/mfa"
	domainmfa "github.com/authcore/internal/domain/mfa"
	"github.com/authcore/internal/domain/jwk"
	"github.com/authcore/internal/domain/token"
	"github.com/stretchr/testify/assert"
)

// --- MFA mocks ---

type mockMFATOTPRepo struct {
	enrollments map[string]domainmfa.TOTPEnrollment
}

func newMockMFATOTPRepo() *mockMFATOTPRepo {
	return &mockMFATOTPRepo{enrollments: make(map[string]domainmfa.TOTPEnrollment)}
}

func (m *mockMFATOTPRepo) Store(_ context.Context, e domainmfa.TOTPEnrollment) error {
	m.enrollments[e.ID] = e
	return nil
}
func (m *mockMFATOTPRepo) GetBySubject(_ context.Context, tenantID, subject string) (domainmfa.TOTPEnrollment, error) {
	for _, e := range m.enrollments {
		if e.TenantID == tenantID && e.Subject == subject {
			return e, nil
		}
	}
	return domainmfa.TOTPEnrollment{}, errors.New("not found")
}
func (m *mockMFATOTPRepo) Confirm(_ context.Context, id string) error {
	e := m.enrollments[id]
	e.Confirmed = true
	m.enrollments[id] = e
	return nil
}
func (m *mockMFATOTPRepo) Delete(_ context.Context, id string) error {
	delete(m.enrollments, id)
	return nil
}

type mockMFAChallengeRepo struct {
	challenges map[string]domainmfa.MFAChallenge
}

func newMockMFAChallengeRepo() *mockMFAChallengeRepo {
	return &mockMFAChallengeRepo{challenges: make(map[string]domainmfa.MFAChallenge)}
}

func (m *mockMFAChallengeRepo) Store(_ context.Context, c domainmfa.MFAChallenge) error {
	m.challenges[c.ID] = c
	return nil
}
func (m *mockMFAChallengeRepo) GetByID(_ context.Context, id string) (domainmfa.MFAChallenge, error) {
	c, ok := m.challenges[id]
	if !ok {
		return domainmfa.MFAChallenge{}, errors.New("not found")
	}
	return c, nil
}
func (m *mockMFAChallengeRepo) MarkVerified(_ context.Context, id string) error {
	c := m.challenges[id]
	c.Verified = true
	m.challenges[id] = c
	return nil
}
func (m *mockMFAChallengeRepo) Delete(_ context.Context, id string) error {
	delete(m.challenges, id)
	return nil
}

type mockMFAJWKRepo struct{}
func (m *mockMFAJWKRepo) Store(_ context.Context, _ jwk.KeyPair) error { return nil }
func (m *mockMFAJWKRepo) GetActive(_ context.Context, _ string) (jwk.KeyPair, error) {
	return jwk.KeyPair{ID: "kid", Algorithm: "RS256", PrivateKey: []byte("key")}, nil
}
func (m *mockMFAJWKRepo) GetAllPublic(_ context.Context, _ string) ([]jwk.KeyPair, error) { return nil, nil }
func (m *mockMFAJWKRepo) Deactivate(_ context.Context, _ string) error { return nil }

type mockMFAGen struct{}
func (m *mockMFAGen) GenerateRSA() ([]byte, []byte, error) { return nil, nil, nil }
func (m *mockMFAGen) GenerateEC() ([]byte, []byte, error) { return nil, nil, nil }

type mockMFAConv struct{}
func (m *mockMFAConv) PEMToPublicJWK(_ []byte, _ string, _ string) (jwk.PublicJWK, error) { return jwk.PublicJWK{}, nil }

type mockMFACodeRepo struct{}
func (m *mockMFACodeRepo) Store(_ context.Context, _ token.AuthorizationCode) error { return nil }
func (m *mockMFACodeRepo) Consume(_ context.Context, _ string) (token.AuthorizationCode, error) {
	return token.AuthorizationCode{}, errors.New("not found")
}

type mockMFASigner struct{}
func (m *mockMFASigner) Sign(_ token.Claims, _ string, _ []byte, _ string) (string, error) {
	return "mock-jwt", nil
}

func newMFATestService() *mfasvc.Service {
	jwksSvc := jwks.NewService(&mockMFAJWKRepo{}, &mockMFAGen{}, &mockMFAConv{}, slog.Default())
	authSvc := auth.NewService(&mockMFACodeRepo{}, jwksSvc, &mockMFASigner{}, slog.Default())
	return mfasvc.NewService(newMockMFATOTPRepo(), newMockMFAChallengeRepo(), authSvc, slog.Default())
}

// --- Tests ---

func TestMFAHandler_Enroll(t *testing.T) {
	h := NewMFAHandler(newMFATestService())

	body := `{"subject":"user-1"}`
	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/enroll", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleEnroll(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "otpauth://")
}

func TestMFAHandler_Enroll_MethodNotAllowed(t *testing.T) {
	h := NewMFAHandler(newMFATestService())

	req := httptest.NewRequest(http.MethodGet, "/mfa/totp/enroll", nil)
	w := httptest.NewRecorder()

	h.HandleEnroll(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMFAHandler_Confirm_NotEnrolled(t *testing.T) {
	h := NewMFAHandler(newMFATestService())

	body := `{"subject":"user-1","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/confirm", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleConfirm(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMFAHandler_Confirm_MethodNotAllowed(t *testing.T) {
	h := NewMFAHandler(newMFATestService())

	req := httptest.NewRequest(http.MethodGet, "/mfa/totp/confirm", nil)
	w := httptest.NewRecorder()

	h.HandleConfirm(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMFAHandler_Verify_ChallengeNotFound(t *testing.T) {
	h := NewMFAHandler(newMFATestService())

	body := `{"challenge_id":"nonexistent","method":"totp","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleVerify(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMFAHandler_Verify_MethodNotAllowed(t *testing.T) {
	h := NewMFAHandler(newMFATestService())

	req := httptest.NewRequest(http.MethodGet, "/mfa/verify", nil)
	w := httptest.NewRecorder()

	h.HandleVerify(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMFAHandler_Verify_Success(t *testing.T) {
	totpRepo := newMockMFATOTPRepo()
	secret := []byte("12345678901234567890")
	totpRepo.enrollments["e1"] = domainmfa.TOTPEnrollment{
		ID: "e1", Subject: "user-1", TenantID: "", Secret: secret, Confirmed: true,
	}

	challengeRepo := newMockMFAChallengeRepo()
	challengeRepo.challenges["ch1"] = domainmfa.MFAChallenge{
		ID: "ch1", Subject: "user-1", TenantID: "",
		ExpiresAt:           time.Now().UTC().Add(5 * time.Minute),
		OriginalClientID:    "client-1",
		OriginalRedirectURI: "https://example.com/cb",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}

	jwksSvc := jwks.NewService(&mockMFAJWKRepo{}, &mockMFAGen{}, &mockMFAConv{}, slog.Default())
	authSvc := auth.NewService(&mockMFACodeRepo{}, jwksSvc, &mockMFASigner{}, slog.Default())
	svc := mfasvc.NewService(totpRepo, challengeRepo, authSvc, slog.Default())
	h := NewMFAHandler(svc)

	code := domainmfa.GenerateTOTP(secret, time.Now().UTC())
	body := `{"challenge_id":"ch1","method":"totp","code":"` + code + `"}`
	req := httptest.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleVerify(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "code")
}
