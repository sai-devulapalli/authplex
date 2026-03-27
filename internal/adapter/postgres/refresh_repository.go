package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/authcore/internal/domain/token"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// RefreshTokenRepository implements token.RefreshTokenRepository using PostgreSQL.
type RefreshTokenRepository struct {
	db *sql.DB
}

// NewRefreshTokenRepository creates a new PostgreSQL-backed refresh token repository.
func NewRefreshTokenRepository(db *sql.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

var _ token.RefreshTokenRepository = (*RefreshTokenRepository)(nil)

func (r *RefreshTokenRepository) Store(ctx context.Context, rt token.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (id, token, client_id, subject, tenant_id, scope, family_id, expires_at, created_at, rotated)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.db.ExecContext(ctx, query,
		rt.ID, rt.Token, rt.ClientID, rt.Subject, rt.TenantID,
		rt.Scope, rt.FamilyID, rt.ExpiresAt, rt.CreatedAt, rt.Rotated,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to store refresh token", err)
	}
	return nil
}

func (r *RefreshTokenRepository) GetByToken(ctx context.Context, tok string) (token.RefreshToken, error) {
	query := `SELECT id, token, client_id, subject, tenant_id, scope, family_id, expires_at, created_at, revoked_at, rotated
		FROM refresh_tokens WHERE token = $1`

	var rt token.RefreshToken
	var revokedAt *time.Time

	err := r.db.QueryRowContext(ctx, query, tok).Scan(
		&rt.ID, &rt.Token, &rt.ClientID, &rt.Subject, &rt.TenantID,
		&rt.Scope, &rt.FamilyID, &rt.ExpiresAt, &rt.CreatedAt, &revokedAt, &rt.Rotated,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return token.RefreshToken{}, apperrors.New(apperrors.ErrNotFound, "refresh token not found")
		}
		return token.RefreshToken{}, apperrors.Wrap(apperrors.ErrInternal, "failed to query refresh token", err)
	}
	rt.RevokedAt = revokedAt
	return rt, nil
}

func (r *RefreshTokenRepository) RevokeByToken(ctx context.Context, tok string) error {
	query := `UPDATE refresh_tokens SET revoked_at = $1 WHERE token = $2 AND revoked_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, time.Now().UTC(), tok)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to revoke refresh token", err)
	}
	return nil
}

func (r *RefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string) error {
	query := `UPDATE refresh_tokens SET revoked_at = $1 WHERE family_id = $2 AND revoked_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, time.Now().UTC(), familyID)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to revoke token family", err)
	}
	return nil
}
