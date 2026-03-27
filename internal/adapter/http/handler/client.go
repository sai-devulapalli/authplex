package handler

import (
	"net/http"
	"strconv"
	"strings"

	clientsvc "github.com/authcore/internal/application/client"
	"github.com/authcore/pkg/sdk/httputil"
)

// ClientHandler serves the client management API.
type ClientHandler struct {
	svc *clientsvc.Service
}

// NewClientHandler creates a new ClientHandler.
func NewClientHandler(svc *clientsvc.Service) *ClientHandler {
	return &ClientHandler{svc: svc}
}

// HandleClients serves /tenants/{tenant_id}/clients (POST, GET).
func (h *ClientHandler) HandleClients(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	if tenantID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id is required")) //nolint:errcheck
		return
	}

	switch r.Method {
	case http.MethodPost:
		var req clientsvc.CreateClientRequest
		if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		req.TenantID = tenantID
		created, appErr := h.svc.Create(r.Context(), req)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusCreated, created) //nolint:errcheck

	case http.MethodGet:
		offset, _ := strconv.Atoi(httputil.QueryParam(r, "offset", "0"))
		limit, _ := strconv.Atoi(httputil.QueryParam(r, "limit", "20"))
		clients, total, appErr := h.svc.List(r.Context(), tenantID, offset, limit)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"clients": clients, "total": total, "offset": offset, "limit": limit,
		}) //nolint:errcheck

	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// HandleClient serves /tenants/{tenant_id}/clients/{client_id} (GET, PUT, DELETE).
func (h *ClientHandler) HandleClient(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	clientID := extractPathSegment(r.URL.Path, "clients", 1)
	if tenantID == "" || clientID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id and client_id are required")) //nolint:errcheck
		return
	}

	switch r.Method {
	case http.MethodGet:
		resp, appErr := h.svc.Get(r.Context(), clientID, tenantID)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck

	case http.MethodPut:
		var req clientsvc.UpdateClientRequest
		if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		req.TenantID = tenantID
		resp, appErr := h.svc.Update(r.Context(), clientID, req)
		if appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck

	case http.MethodDelete:
		if appErr := h.svc.Delete(r.Context(), clientID, tenantID); appErr != nil {
			httputil.WriteError(w, appErr) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// extractPathSegment extracts the segment after the given key in a URL path.
// e.g., extractPathSegment("/tenants/t1/clients/c1", "tenants", 1) returns "t1"
func extractPathSegment(path, key string, offset int) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		if part == key && i+offset < len(parts) {
			return parts[i+offset]
		}
	}
	return ""
}
