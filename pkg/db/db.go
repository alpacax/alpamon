package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/glebarez/go-sqlite"
	"github.com/rs/zerolog/log"
)

const dbFileName = "alpamon.db"

func InitDB() *ent.Client {
	dataDir := utils.DataDir()
	fileName := fmt.Sprintf("%s/%s", dataDir, dbFileName)
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		fileName, _ = filepath.Abs(dbFileName)
	}

	dbFile, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0750)
	if err != nil {
		log.Error().Err(err).Msgf("failed to open db file: %v.", err)
		_, _ = fmt.Fprintf(os.Stderr, "Failed to open db file: %v\n", err)
		os.Exit(1)
	}

	sql.Register("sqlite3", &sqlite.Driver{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	err = RunMigration(dbFile.Name(), ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to migrate db: %v.", err)
		os.Exit(1)
	}

	dbManager := NewDBClientManager(dbFile.Name())
	client, err := dbManager.GetClient()
	if err != nil {
		log.Error().Err(err).Msgf("failed to get db client: %v.", err)
		os.Exit(1)
	}

	return client
}

func InitTestDB(path string) *ent.Client {
	fileName, _ := filepath.Abs(path)
	dbFile, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0750)
	if err != nil {
		log.Error().Err(err).Msgf("failed to open test db file: %v.", err)
		_, _ = fmt.Fprintf(os.Stderr, "Failed to open test db file: %v\n", err)
		os.Exit(1)
	}
	// We only needed OpenFile to create-on-absence; the filename (and
	// the sqlite driver, which opens its own handle) is what the
	// migration and ent client consume. Keeping this handle open would
	// prevent the test's TearDownSuite from os.Remove'ing the file on
	// Windows, where open handles block deletion.
	_ = dbFile.Close()

	sql.Register("sqlite3", &sqlite.Driver{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	err = RunMigration(fileName, ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to migrate test db: %v.", err)
		os.Exit(1)
	}

	dbManager := NewDBClientManager(fileName)
	client, err := dbManager.GetClient()
	if err != nil {
		log.Error().Err(err).Msgf("failed to get db client: %v.", err)
		os.Exit(1)
	}

	return client
}
