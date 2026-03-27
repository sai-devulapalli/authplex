package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// RunMigrations executes all SQL migration files in order.
// Uses a migrations tracking table to avoid re-running.
func RunMigrations(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	// Create tracking table
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		filename TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
	if err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	// Read migration files
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	// Sort by filename (sequential order)
	var filenames []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			filenames = append(filenames, entry.Name())
		}
	}
	sort.Strings(filenames)

	// Apply each migration
	for _, filename := range filenames {
		// Check if already applied
		var count int
		err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE filename = $1", filename).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check migration status for %s: %w", filename, err)
		}
		if count > 0 {
			continue
		}

		// Read and execute
		content, err := migrationFS.ReadFile("migrations/" + filename)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", filename, err)
		}

		if _, err := db.ExecContext(ctx, string(content)); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", filename, err)
		}

		// Record as applied
		if _, err := db.ExecContext(ctx, "INSERT INTO schema_migrations (filename) VALUES ($1)", filename); err != nil {
			return fmt.Errorf("failed to record migration %s: %w", filename, err)
		}

		logger.Info("migration applied", "file", filename)
	}

	return nil
}
