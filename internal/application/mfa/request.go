package mfa

// EnrollRequest is the DTO for TOTP enrollment.
type EnrollRequest struct {
	Subject  string `json:"subject"`
	TenantID string `json:"-"`
}

// EnrollResponse is returned after TOTP enrollment.
type EnrollResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
}

// VerifyRequest is the DTO for TOTP code verification / confirmation.
type VerifyRequest struct {
	Subject  string `json:"subject"`
	Code     string `json:"code"`
	TenantID string `json:"-"`
}

// MFAVerifyRequest is the DTO for completing an MFA challenge.
type MFAVerifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	Method      string `json:"method"`
	Code        string `json:"code"`
}

// ChallengeResponse is returned when MFA is required.
type ChallengeResponse struct {
	MFARequired bool     `json:"mfa_required"`
	ChallengeID string   `json:"challenge_id"`
	Methods     []string `json:"methods"`
	ExpiresIn   int      `json:"expires_in"`
}

// CreateChallengeRequest contains the data to create an MFA challenge.
type CreateChallengeRequest struct {
	Subject             string
	TenantID            string
	Methods             []string
	OriginalClientID    string
	OriginalRedirectURI string
	OriginalScope       string
	OriginalState       string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}
