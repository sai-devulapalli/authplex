package tenant

import (
	"context"
	"log/slog"

	"github.com/authcore/internal/config"
	"github.com/authcore/internal/domain/tenant"
	apperrors "github.com/authcore/pkg/sdk/errors"
)

// Service provides tenant management operations.
type Service struct {
	repo   tenant.Repository
	logger *slog.Logger
}

// NewService creates a new tenant service.
func NewService(repo tenant.Repository, logger *slog.Logger) *Service {
	return &Service{
		repo:   repo,
		logger: logger,
	}
}

// Create creates a new tenant.
func (s *Service) Create(ctx context.Context, req CreateTenantRequest) (tenant.Tenant, *apperrors.AppError) {
	t, err := tenant.NewTenant(req.ID, req.Domain, req.Issuer, req.Algorithm)
	if err != nil {
		return tenant.Tenant{}, apperrors.Wrap(apperrors.ErrBadRequest, "invalid tenant", err)
	}

	if err := s.repo.Create(ctx, t); err != nil {
		return tenant.Tenant{}, apperrors.Wrap(apperrors.ErrInternal, "failed to create tenant", err)
	}

	s.logger.Info("tenant created", "tenant_id", t.ID, "domain", t.Domain)
	return t, nil
}

// Get returns a tenant by ID.
func (s *Service) Get(ctx context.Context, id string) (tenant.Tenant, *apperrors.AppError) {
	t, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return tenant.Tenant{}, apperrors.Wrap(apperrors.ErrNotFound, "tenant not found", err)
	}
	if t.IsDeleted() {
		return tenant.Tenant{}, apperrors.New(apperrors.ErrNotFound, "tenant not found")
	}
	return t, nil
}

// Update updates an existing tenant.
func (s *Service) Update(ctx context.Context, id string, req UpdateTenantRequest) (tenant.Tenant, *apperrors.AppError) {
	t, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return tenant.Tenant{}, apperrors.Wrap(apperrors.ErrNotFound, "tenant not found", err)
	}

	if req.Domain != "" {
		t.Domain = req.Domain
	}
	if req.Issuer != "" {
		t.Issuer = req.Issuer
	}

	if err := s.repo.Update(ctx, t); err != nil {
		return tenant.Tenant{}, apperrors.Wrap(apperrors.ErrInternal, "failed to update tenant", err)
	}

	s.logger.Info("tenant updated", "tenant_id", t.ID)
	return t, nil
}

// Delete soft-deletes a tenant.
func (s *Service) Delete(ctx context.Context, id string) *apperrors.AppError {
	if err := s.repo.Delete(ctx, id); err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to delete tenant", err)
	}
	s.logger.Info("tenant deleted", "tenant_id", id)
	return nil
}

// List returns a paginated list of tenants.
func (s *Service) List(ctx context.Context, offset, limit int) ([]tenant.Tenant, int, *apperrors.AppError) {
	tenants, total, err := s.repo.List(ctx, offset, limit)
	if err != nil {
		return nil, 0, apperrors.Wrap(apperrors.ErrInternal, "failed to list tenants", err)
	}
	return tenants, total, nil
}

// Resolve finds a tenant by ID or domain based on the tenant mode.
func (s *Service) Resolve(ctx context.Context, identifier string, mode config.TenantMode) (tenant.Tenant, *apperrors.AppError) {
	var t tenant.Tenant
	var err error

	switch mode {
	case config.TenantModeHeader:
		t, err = s.repo.GetByID(ctx, identifier)
	case config.TenantModeDomain:
		t, err = s.repo.GetByDomain(ctx, identifier)
	default:
		return tenant.Tenant{}, apperrors.New(apperrors.ErrInternal, "unknown tenant mode")
	}

	if err != nil {
		return tenant.Tenant{}, apperrors.Wrap(apperrors.ErrNotFound, "tenant not found", err)
	}
	if t.IsDeleted() {
		return tenant.Tenant{}, apperrors.New(apperrors.ErrNotFound, "tenant not found")
	}
	return t, nil
}
