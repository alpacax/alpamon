package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/rs/zerolog/log"
)

//go:embed migration/*
var migrations embed.FS

// MigrationFile represents a migration file with its metadata
type MigrationFile struct {
	Version     string
	Description string
	Filename    string
	Content     string
}

// RunMigration executes database migrations from embedded migration files
func RunMigration(path string, ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		log.Error().Err(err).Msg("context cancelled before migration")
		return err
	}

	// Open database connection
	db, err := sql.Open("sqlite", path)
	if err != nil {
		log.Error().Err(err).Msg("failed to open database")
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Create migration tracking table if not exists
	err = createMigrationTable(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("failed to create migration table")
		return fmt.Errorf("failed to create migration table: %w", err)
	}

	// Read migration files
	migrationFiles, err := readMigrationFiles()
	if err != nil {
		log.Error().Err(err).Msg("failed to read migration files")
		return fmt.Errorf("failed to read migration files: %w", err)
	}

	// Get already applied migrations
	appliedVersions, err := getAppliedMigrations(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("failed to get applied migrations")
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Execute each migration
	appliedCount := 0
	for _, mf := range migrationFiles {
		if appliedVersions[mf.Version] {
			log.Debug().Msgf("Migration already applied, skipping: %s", mf.Filename)
			continue
		}

		log.Info().Msgf("applying migration: %s", mf.Filename)
		if err := applyMigration(ctx, db, mf); err != nil {
			log.Error().Err(err).Msgf("Failed to apply migration: %s", mf.Filename)
			return fmt.Errorf("migration %s failed: %w", mf.Version, err)
		}

		log.Info().Msgf("Migration applied successfully: %s", mf.Filename)
		appliedCount++
	}

	if appliedCount > 0 {
		log.Info().Msgf("All migrations completed: %d migration(s) applied", appliedCount)
	} else {
		log.Info().Msg("All migrations up to date: no new migrations to apply")
	}
	return nil
}

// createMigrationTable creates the atlas_schema_revisions table if it doesn't exist
func createMigrationTable(ctx context.Context, db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS atlas_schema_revisions (
		version TEXT NOT NULL PRIMARY KEY,
		description TEXT NOT NULL,
		type INTEGER NOT NULL DEFAULT 2,
		applied INTEGER NOT NULL DEFAULT 0,
		total INTEGER NOT NULL DEFAULT 0,
		executed_at DATETIME NOT NULL,
		execution_time INTEGER NOT NULL,
		error TEXT NULL,
		error_stmt TEXT NULL,
		hash TEXT NOT NULL DEFAULT '',
		partial_hashes TEXT NULL,
		operator_version TEXT NOT NULL
	);`

	_, err := db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create migration table: %w", err)
	}

	return nil
}

// readMigrationFiles reads and parses all migration files from the embedded filesystem
func readMigrationFiles() ([]MigrationFile, error) {
	migrationFS, err := fs.Sub(migrations, "migration")
	if err != nil {
		return nil, fmt.Errorf("failed to get migration directory: %w", err)
	}

	entries, err := fs.ReadDir(migrationFS, ".")
	if err != nil {
		return nil, fmt.Errorf("failed to read migration directory: %w", err)
	}

	var files []MigrationFile
	for _, entry := range entries {
		// Skip directories and non-.sql files
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		// Read file content
		content, err := fs.ReadFile(migrationFS, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", entry.Name(), err)
		}

		// Skip empty files or files with only whitespace
		contentStr := strings.TrimSpace(string(content))
		if contentStr == "" {
			log.Debug().Msgf("Skip empty migration file: %s", entry.Name())
			continue
		}

		// Parse filename: {version}_{description}.sql
		version, description := parseMigrationFilename(entry.Name())

		files = append(files, MigrationFile{
			Version:     version,
			Description: description,
			Filename:    entry.Name(),
			Content:     contentStr,
		})
	}

	// Sort by version (timestamp)
	sort.Slice(files, func(i, j int) bool {
		return files[i].Version < files[j].Version
	})

	return files, nil
}

// parseMigrationFilename extracts version and description from filename
// Expected format: {version}_{description}.sql
// Example: "20250116061438_init_schemas.sql" → ("20250116061438", "init_schemas")
func parseMigrationFilename(filename string) (version, description string) {
	// Remove .sql extension
	name := strings.TrimSuffix(filename, filepath.Ext(filename))

	// Split by first underscore
	parts := strings.SplitN(name, "_", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	// If parsing fails, use entire name as version
	return name, ""
}

// getAppliedMigrations returns a map of already applied migration versions
func getAppliedMigrations(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	query := "SELECT version FROM atlas_schema_revisions"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("failed to scan version: %w", err)
		}
		applied[version] = true
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return applied, nil
}

// applyMigration executes a migration within a transaction
func applyMigration(ctx context.Context, db *sql.DB, mf MigrationFile) error {
	startTime := time.Now()

	// Begin transaction
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		rbErr := tx.Rollback()
		if rbErr != nil && rbErr != sql.ErrTxDone {
			log.Error().Err(rbErr).Msg("failed to rollback transaction")
		}
	}()

	// Execute migration SQL
	_, err = tx.ExecContext(ctx, mf.Content)
	if err != nil {
		// Log the SQL that failed for debugging
		log.Error().Err(err).Msgf("migration SQL execution failed: %s", mf.Content)

		// Record failure in tracking table (use separate connection since tx will rollback)
		_ = recordMigrationFailure(ctx, db, mf, err, startTime)
		return fmt.Errorf("failed to execute migration: %w", err)
	}

	// Record success in tracking table
	if err := recordMigrationSuccess(ctx, tx, mf, startTime); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// recordMigrationSuccess records a successful migration in the tracking table
func recordMigrationSuccess(ctx context.Context, tx *sql.Tx, mf MigrationFile, startTime time.Time) error {
	executionTime := time.Since(startTime).Microseconds()

	query := `
	INSERT INTO atlas_schema_revisions
		(version, description, type, applied, total, executed_at, execution_time, operator_version, hash)
	VALUES
		(?, ?, 2, 1, 1, ?, ?, 'alpamon', '')
	`

	_, err := tx.ExecContext(ctx, query,
		mf.Version,
		mf.Description,
		time.Now().Format(time.RFC3339),
		executionTime,
	)

	if err != nil {
		return fmt.Errorf("failed to insert migration record: %w", err)
	}

	return nil
}

// recordMigrationFailure records a failed migration in the tracking table
// Uses a separate connection since the transaction will be rolled back
func recordMigrationFailure(ctx context.Context, db *sql.DB, mf MigrationFile, migrationErr error, startTime time.Time) error {
	executionTime := time.Since(startTime).Microseconds()

	query := `
	INSERT INTO atlas_schema_revisions
		(version, description, type, applied, total, executed_at, execution_time, error, operator_version, hash)
	VALUES
		(?, ?, 2, 0, 1, ?, ?, ?, 'alpamon', '')
	`

	_, err := db.ExecContext(ctx, query,
		mf.Version,
		mf.Description,
		time.Now().Format(time.RFC3339),
		executionTime,
		migrationErr.Error(),
	)

	if err != nil {
		log.Error().Err(err).Msg("failed to record migration failure")
		return err
	}

	return nil
}
