package cache

import (
	"context"
	"sync"
	"time"

	"github.com/authcore/internal/domain/token"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// InMemoryRefreshRepository implements token.RefreshTokenRepository.
type InMemoryRefreshRepository struct {
	mu     sync.Mutex
	tokens map[string]token.RefreshToken
}

// NewInMemoryRefreshRepository creates a new in-memory refresh token repository.
func NewInMemoryRefreshRepository() *InMemoryRefreshRepository {
	return &InMemoryRefreshRepository{tokens: make(map[string]token.RefreshToken)}
}

var _ token.RefreshTokenRepository = (*InMemoryRefreshRepository)(nil)

func (r *InMemoryRefreshRepository) Store(_ context.Context, rt token.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[rt.Token] = rt
	return nil
}

func (r *InMemoryRefreshRepository) GetByToken(_ context.Context, tok string) (token.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rt, ok := r.tokens[tok]
	if !ok {
		return token.RefreshToken{}, apperrors.New(apperrors.ErrNotFound, "refresh token not found")
	}
	return rt, nil
}

func (r *InMemoryRefreshRepository) RevokeByToken(_ context.Context, tok string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rt, ok := r.tokens[tok]
	if !ok {
		return apperrors.New(apperrors.ErrNotFound, "refresh token not found")
	}
	now := time.Now().UTC()
	rt.RevokedAt = &now
	r.tokens[tok] = rt
	return nil
}

func (r *InMemoryRefreshRepository) RevokeFamily(_ context.Context, familyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	for k, rt := range r.tokens {
		if rt.FamilyID == familyID {
			rt.RevokedAt = &now
			r.tokens[k] = rt
		}
	}
	return nil
}
