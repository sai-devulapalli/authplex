package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSocialHandler_MethodNotAllowed(t *testing.T) {
	// SocialHandler with nil service to test method check
	h := NewSocialHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/callback?code=c&state=s", nil)
	w := httptest.NewRecorder()

	h.HandleCallback(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
