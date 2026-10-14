package usage

import (
	"context"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/testutil"
	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/db"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/diskusage"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/hourlydiskusage"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var dbFileName = "hourly_disk_usage.db"

type HourlyDiskUsageCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *HourlyDiskUsageCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.HourlyDiskUsage,
		Name:     string(base.HourlyDiskUsage) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *HourlyDiskUsageCheckSuite) TearDownSuite() {
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

func (suite *HourlyDiskUsageCheckSuite) TestGetDiskUsage() {
	err := suite.check.GetClient().DiskUsage.Create().
		SetTimestamp(time.Now()).
		SetDevice(uuid.NewString()).
		SetUsage(rand.Float64()).
		SetTotal(int64(rand.Int())).
		SetFree(int64(rand.Int())).
		SetUsed(int64(rand.Int())).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create disk usage.")

	querySet, err := suite.check.getDiskUsage(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get disk usage.")
	assert.NotEmpty(suite.T(), querySet, "Disk usage queryset should not be empty")
}

func (suite *HourlyDiskUsageCheckSuite) TestSaveHourlyDiskUsage() {
	data := []base.CheckResult{
		{
			Timestamp: time.Now(),
			Device:    uuid.NewString(),
			Peak:      50.0,
			Avg:       50.0,
		},
		{
			Timestamp: time.Now(),
			Device:    uuid.NewString(),
			Peak:      50.0,
			Avg:       50.0,
		},
	}

	err := suite.check.saveHourlyDiskUsage(data, suite.ctx)
	assert.NoError(suite.T(), err, "Failed to save hourly disk usage.")
}

func (suite *HourlyDiskUsageCheckSuite) TestDeleteDiskUsage() {
	err := suite.check.GetClient().DiskUsage.Create().
		SetTimestamp(time.Now().Add(-2 * time.Hour)).
		SetDevice(uuid.NewString()).
		SetUsage(rand.Float64()).
		SetTotal(int64(rand.Int())).
		SetFree(int64(rand.Int())).
		SetUsed(int64(rand.Int())).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create disk usage.")

	err = deleteDiskUsage(suite.ctx, suite.client.DiskUsage)
	assert.NoError(suite.T(), err, "Failed to delete disk usage.")
}

func (suite *HourlyDiskUsageCheckSuite) commitFailingCheck() *Check {
	return NewCheck(&base.CheckArgs{
		Type:     base.HourlyDiskUsage,
		Name:     string(base.HourlyDiskUsage) + "_" + uuid.NewString(),
		Interval: time.Second,
		Buffer:   base.NewCheckBuffer(10),
		Client:   testutil.CommitFailingClient(suite.T(), dbFileName),
	}).(*Check)
}

func (suite *HourlyDiskUsageCheckSuite) TestSaveHourlyDiskUsageReturnsCommitErrorAndKeepsRawRows() {
	old := time.Now().Add(-2 * time.Hour)
	suite.Require().NoError(suite.client.DiskUsage.Create().SetTimestamp(old).SetDevice(uuid.NewString()).SetUsage(1).SetTotal(1).SetFree(1).SetUsed(1).Exec(suite.ctx))
	ts := time.Now().Add(-42 * time.Minute)
	data := []base.CheckResult{{Timestamp: ts, Device: uuid.NewString()}}

	err := suite.commitFailingCheck().saveHourlyDiskUsage(data, suite.ctx)

	suite.ErrorIs(err, testutil.ErrCommitFailed)
	stored, err := suite.client.HourlyDiskUsage.Query().Where(hourlydiskusage.TimestampEQ(ts)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.False(stored, "the failed commit must not store the hourly row")
	kept, err := suite.client.DiskUsage.Query().Where(diskusage.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(kept, "the failed commit must not delete the raw row")
}

func (suite *HourlyDiskUsageCheckSuite) TestSaveHourlyDiskUsageDeletesOldRawRows() {
	old := time.Now().Add(-2 * time.Hour)
	suite.Require().NoError(suite.client.DiskUsage.Create().SetTimestamp(old).SetDevice(uuid.NewString()).SetUsage(1).SetTotal(1).SetFree(1).SetUsed(1).Exec(suite.ctx))
	ts := time.Now().Add(-41 * time.Minute)
	data := []base.CheckResult{{Timestamp: ts, Device: uuid.NewString()}}

	err := suite.check.saveHourlyDiskUsage(data, suite.ctx)

	suite.Require().NoError(err)
	stored, err := suite.client.HourlyDiskUsage.Query().Where(hourlydiskusage.TimestampEQ(ts)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(stored)
	kept, err := suite.client.DiskUsage.Query().Where(diskusage.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.False(kept, "the save must delete raw rows older than an hour")
}

func TestHourlyDiskUsageCheckSuite(t *testing.T) {
	suite.Run(t, new(HourlyDiskUsageCheckSuite))
}
