package handler

import (
	"net/http"

	mfasvc "github.com/authcore/internal/application/mfa"
	"github.com/authcore/pkg/sdk/httputil"
)

// MFAHandler serves MFA endpoints.
type MFAHandler struct {
	svc *mfasvc.Service
}

// NewMFAHandler creates a new MFAHandler.
func NewMFAHandler(svc *mfasvc.Service) *MFAHandler {
	return &MFAHandler{svc: svc}
}

// HandleEnroll serves POST /mfa/totp/enroll.
func (h *MFAHandler) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.EnrollRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.EnrollTOTP(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// HandleConfirm serves POST /mfa/totp/confirm.
func (h *MFAHandler) HandleConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.VerifyRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	if appErr := h.svc.ConfirmTOTP(r.Context(), req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "confirmed"}) //nolint:errcheck
}

// HandleVerify serves POST /mfa/verify — completes an MFA challenge.
func (h *MFAHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.MFAVerifyRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	resp, appErr := h.svc.VerifyMFA(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"code":  resp.Code,
		"state": resp.State,
	}) //nolint:errcheck
}
