package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMigrationFilename(t *testing.T) {
	tests := []struct {
		name                string
		filename            string
		expectedVersion     string
		expectedDescription string
	}{
		{
			name:                "standard migration file",
			filename:            "20250116061438_init_schemas.sql",
			expectedVersion:     "20250116061438",
			expectedDescription: "init_schemas",
		},
		{
			name:                "migration with underscores in description",
			filename:            "20250313082232_alter_disk_usage_fields.sql",
			expectedVersion:     "20250313082232",
			expectedDescription: "alter_disk_usage_fields",
		},
		{
			name:                "migration without description",
			filename:            "20250101000000.sql",
			expectedVersion:     "20250101000000",
			expectedDescription: "",
		},
		{
			name:                "no extension",
			filename:            "20250101000000_test",
			expectedVersion:     "20250101000000",
			expectedDescription: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, description := parseMigrationFilename(tt.filename)
			assert.Equal(t, tt.expectedVersion, version)
			assert.Equal(t, tt.expectedDescription, description)
		})
	}
}

func TestCreateMigrationTable(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	ctx := context.Background()

	// Create migration table
	err = createMigrationTable(ctx, db)
	require.NoError(t, err)

	// Verify table exists
	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='atlas_schema_revisions'").Scan(&tableName)
	require.NoError(t, err)
	assert.Equal(t, "atlas_schema_revisions", tableName)

	// Verify table schema
	var sql string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='atlas_schema_revisions'").Scan(&sql)
	require.NoError(t, err)
	assert.Contains(t, sql, "version TEXT NOT NULL PRIMARY KEY")
	assert.Contains(t, sql, "description TEXT NOT NULL")
	assert.Contains(t, sql, "executed_at DATETIME NOT NULL")

	// Test idempotency - creating table again should not error
	err = createMigrationTable(ctx, db)
	require.NoError(t, err)
}

func TestGetAppliedMigrations(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	ctx := context.Background()

	// Create table
	err = createMigrationTable(ctx, db)
	require.NoError(t, err)

	// Test empty table
	applied, err := getAppliedMigrations(ctx, db)
	require.NoError(t, err)
	assert.Empty(t, applied)

	// Insert some migrations
	_, err = db.ExecContext(ctx, `
		INSERT INTO atlas_schema_revisions
		(version, description, type, applied, total, executed_at, execution_time, operator_version, hash)
		VALUES
		('20250101000000', 'test1', 2, 1, 1, ?, 1000, 'alpamon', ''),
		('20250102000000', 'test2', 2, 1, 1, ?, 2000, 'alpamon', '')
	`, time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339))
	require.NoError(t, err)

	// Test with applied migrations
	applied, err = getAppliedMigrations(ctx, db)
	require.NoError(t, err)
	assert.Len(t, applied, 2)
	assert.True(t, applied["20250101000000"])
	assert.True(t, applied["20250102000000"])
	assert.False(t, applied["20250103000000"])
}

func TestRunMigration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run migrations
	err := RunMigration(dbPath, ctx)
	require.NoError(t, err)

	// Verify database was created
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	// Check if cp_us table exists (from init_schemas.sql)
	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='cp_us'").Scan(&tableName)
	require.NoError(t, err)
	assert.Equal(t, "cp_us", tableName)

	// Check if disk_usages table exists
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='disk_usages'").Scan(&tableName)
	require.NoError(t, err)
	assert.Equal(t, "disk_usages", tableName)

	// Verify migration records
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM atlas_schema_revisions").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "should have 2 migration records")

	// Verify migration versions
	rows, err := db.Query("SELECT version, description FROM atlas_schema_revisions ORDER BY version")
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	expectedMigrations := []struct {
		version     string
		description string
	}{
		{"20250116061438", "init_schemas"},
		{"20250313082232", "alter_disk_usage_fields"},
	}

	i := 0
	for rows.Next() {
		var version, description string
		err = rows.Scan(&version, &description)
		require.NoError(t, err)
		assert.Equal(t, expectedMigrations[i].version, version)
		assert.Equal(t, expectedMigrations[i].description, description)
		i++
	}
	assert.Equal(t, 2, i, "should have iterated over 2 migrations")
}

func TestRunMigrationIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	ctx := context.Background()

	// Run migrations first time
	err := RunMigration(dbPath, ctx)
	require.NoError(t, err)

	// Run migrations second time - should not error
	err = RunMigration(dbPath, ctx)
	require.NoError(t, err)

	// Verify still only 2 migrations
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM atlas_schema_revisions").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "migrations should not be re-applied")
}

func TestRunMigrationContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Run migrations with cancelled context
	err := RunMigration(dbPath, ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestReadMigrationFiles(t *testing.T) {
	files, err := readMigrationFiles()
	require.NoError(t, err)

	// Should have at least 2 migration files
	assert.GreaterOrEqual(t, len(files), 2)

	// Verify files are sorted by version
	for i := 1; i < len(files); i++ {
		assert.True(t, files[i-1].Version < files[i].Version,
			"migrations should be sorted by version: %s should be before %s",
			files[i-1].Version, files[i].Version)
	}

	// Verify first migration
	if len(files) > 0 {
		assert.Equal(t, "20250116061438", files[0].Version)
		assert.Equal(t, "init_schemas", files[0].Description)
		assert.NotEmpty(t, files[0].Content)
		assert.Contains(t, files[0].Content, "CREATE TABLE")
	}

	// Verify second migration
	if len(files) > 1 {
		assert.Equal(t, "20250313082232", files[1].Version)
		assert.Equal(t, "alter_disk_usage_fields", files[1].Description)
		assert.NotEmpty(t, files[1].Content)
		assert.Contains(t, files[1].Content, "PRAGMA foreign_keys")
	}
}

func TestRecordMigrationSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()

	// Create table
	err = createMigrationTable(ctx, db)
	require.NoError(t, err)

	// Begin transaction
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() {
		_ = tx.Rollback() // Ignore error in test cleanup
	}()

	// Record success
	mf := MigrationFile{
		Version:     "20250101000000",
		Description: "test_migration",
		Filename:    "20250101000000_test_migration.sql",
		Content:     "CREATE TABLE test (id INTEGER);",
	}

	startTime := time.Now().Add(-100 * time.Millisecond)
	err = recordMigrationSuccess(ctx, tx, mf, startTime)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// Verify record
	var version, description, operatorVersion string
	var executionTime int64
	err = db.QueryRow(`
		SELECT version, description, operator_version, execution_time
		FROM atlas_schema_revisions
		WHERE version = ?
	`, "20250101000000").Scan(&version, &description, &operatorVersion, &executionTime)
	require.NoError(t, err)

	assert.Equal(t, "20250101000000", version)
	assert.Equal(t, "test_migration", description)
	assert.Equal(t, "alpamon", operatorVersion)
	assert.Greater(t, executionTime, int64(0), "execution time should be recorded")
}

func TestApplyMigration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()

	// Create tracking table
	err = createMigrationTable(ctx, db)
	require.NoError(t, err)

	// Apply a test migration
	mf := MigrationFile{
		Version:     "20250101000000",
		Description: "create_test_table",
		Filename:    "20250101000000_create_test_table.sql",
		Content:     "CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT);",
	}

	err = applyMigration(ctx, db, mf)
	require.NoError(t, err)

	// Verify table was created
	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='test_table'").Scan(&tableName)
	require.NoError(t, err)
	assert.Equal(t, "test_table", tableName)

	// Verify migration was recorded
	var version string
	err = db.QueryRow("SELECT version FROM atlas_schema_revisions WHERE version = ?", "20250101000000").Scan(&version)
	require.NoError(t, err)
	assert.Equal(t, "20250101000000", version)
}

func TestApplyMigrationTransactionRollback(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()

	// Create tracking table
	err = createMigrationTable(ctx, db)
	require.NoError(t, err)

	// Apply a migration with invalid SQL
	mf := MigrationFile{
		Version:     "20250101000000",
		Description: "invalid_migration",
		Filename:    "20250101000000_invalid_migration.sql",
		Content:     "CREATE TABLE test_table (id INTEGER PRIMARY KEY); INVALID SQL STATEMENT;",
	}

	err = applyMigration(ctx, db, mf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to execute migration")

	// Verify table was NOT created (transaction rolled back)
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='test_table'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "table should not exist due to rollback")

	// Note: Migration failure record may not be persisted due to SQLite locking
	// during transaction rollback. This is acceptable as the transaction rollback
	// ensures database consistency.
}
