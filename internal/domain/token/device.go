package token

import "time"

// DeviceCode represents a pending device authorization (RFC 8628).
type DeviceCode struct {
	DeviceCode      string
	UserCode        string
	ClientID        string
	TenantID        string
	Scope           string
	VerificationURI string
	ExpiresAt       time.Time
	Interval        int // polling interval in seconds
	Subject         string
	Authorized      bool
	Denied          bool
}

// IsExpiredDevice returns true if the device code has expired.
func (dc DeviceCode) IsExpiredDevice() bool {
	return time.Now().UTC().After(dc.ExpiresAt)
}

// IsPending returns true if the device code has not been authorized or denied.
func (dc DeviceCode) IsPending() bool {
	return !dc.Authorized && !dc.Denied
}
