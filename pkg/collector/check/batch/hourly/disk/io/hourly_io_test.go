package io

import (
	"context"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/testutil/dbtest"
	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/db"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/diskio"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/hourlydiskio"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var dbFileName = "hourly_io.db"

type HourlyDiskIOCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *HourlyDiskIOCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	suite.check = newCheck(suite.client)
	suite.ctx = context.Background()
}

func (suite *HourlyDiskIOCheckSuite) TearDownSuite() {
	// Close the ent client first. On Windows, os.Remove fails with
	// a sharing violation if the underlying SQLite file handle is still
	// open. On Unix, the unlink succeeds either way, so this is a no-op
	// for Linux/macOS runners.
	if suite.client != nil {
		_ = suite.client.Close()
	}
	err := os.Remove(dbFileName)
	suite.Require().NoError(err, "failed to delete test db file")
}

func (suite *HourlyDiskIOCheckSuite) TestGetDiskIO() {
	err := suite.check.GetClient().DiskIO.Create().
		SetTimestamp(time.Now()).
		SetDevice(uuid.NewString()).
		SetReadBps(rand.Float64()).
		SetWriteBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create disk io.")

	querySet, err := suite.check.getDiskIO(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get disk io.")
	assert.NotEmpty(suite.T(), querySet, "Disk io queryset should not be empty")
}

func (suite *HourlyDiskIOCheckSuite) TestSaveHourlyDiskIO() {
	data := []base.CheckResult{
		{
			Timestamp:    time.Now(),
			Device:       uuid.NewString(),
			PeakWriteBps: rand.Float64(),
			PeakReadBps:  rand.Float64(),
			AvgWriteBps:  rand.Float64(),
			AvgReadBps:   rand.Float64(),
		},
		{
			Timestamp:    time.Now(),
			Device:       uuid.NewString(),
			PeakWriteBps: rand.Float64(),
			PeakReadBps:  rand.Float64(),
			AvgWriteBps:  rand.Float64(),
			AvgReadBps:   rand.Float64(),
		},
	}

	err := suite.check.saveHourlyDiskIO(data, suite.ctx)
	assert.NoError(suite.T(), err, "Failed to save hourly disk io.")
}

func (suite *HourlyDiskIOCheckSuite) TestDeleteDiskIO() {
	err := suite.check.GetClient().DiskIO.Create().
		SetTimestamp(time.Now().Add(-2 * time.Hour)).
		SetDevice(uuid.NewString()).
		SetReadBps(rand.Float64()).
		SetWriteBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create disk io.")

	err = deleteDiskIO(suite.ctx, suite.client.DiskIO)
	assert.NoError(suite.T(), err, "Failed to delete disk io.")
}

func newCheck(client *ent.Client) *Check {
	return NewCheck(&base.CheckArgs{
		Type:     base.HourlyDiskIO,
		Name:     string(base.HourlyDiskIO) + "_" + uuid.NewString(),
		Interval: time.Second,
		Buffer:   base.NewCheckBuffer(10),
		Client:   client,
	}).(*Check)
}

func (suite *HourlyDiskIOCheckSuite) commitFailingCheck() *Check {
	return newCheck(dbtest.CommitFailingClient(suite.T(), dbFileName))
}

func (suite *HourlyDiskIOCheckSuite) TestSaveHourlyDiskIOReturnsCommitErrorAndKeepsRawRows() {
	old := time.Now().Add(-2 * time.Hour)
	suite.Require().NoError(suite.client.DiskIO.Create().SetTimestamp(old).SetDevice(uuid.NewString()).SetReadBps(1).SetWriteBps(1).Exec(suite.ctx))
	ts := time.Now().Add(-42 * time.Minute)
	data := []base.CheckResult{{Timestamp: ts, Device: uuid.NewString()}}

	err := suite.commitFailingCheck().saveHourlyDiskIO(data, suite.ctx)

	suite.ErrorIs(err, dbtest.ErrCommitFailed)
	stored, err := suite.client.HourlyDiskIO.Query().Where(hourlydiskio.TimestampEQ(ts)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.False(stored, "the failed commit must not store the hourly row")
	kept, err := suite.client.DiskIO.Query().Where(diskio.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(kept, "the failed commit must not delete the raw row")
}

func (suite *HourlyDiskIOCheckSuite) TestSaveHourlyDiskIODeletesOldRawRows() {
	old := time.Now().Add(-2 * time.Hour)
	suite.Require().NoError(suite.client.DiskIO.Create().SetTimestamp(old).SetDevice(uuid.NewString()).SetReadBps(1).SetWriteBps(1).Exec(suite.ctx))
	ts := time.Now().Add(-41 * time.Minute)
	data := []base.CheckResult{{Timestamp: ts, Device: uuid.NewString()}}

	err := suite.check.saveHourlyDiskIO(data, suite.ctx)

	suite.Require().NoError(err)
	stored, err := suite.client.HourlyDiskIO.Query().Where(hourlydiskio.TimestampEQ(ts)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(stored)
	kept, err := suite.client.DiskIO.Query().Where(diskio.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.False(kept, "the save must delete raw rows older than an hour")
}

func TestHourlyDiskIOCheckSuite(t *testing.T) {
	suite.Run(t, new(HourlyDiskIOCheckSuite))
}
