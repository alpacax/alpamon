package usage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/testutil/dbtest"
	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/db"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/hourlydiskusage"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var dbFileName = "daily_disk_usage.db"

type DailyDiskUsageCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *DailyDiskUsageCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.DailyDiskUsage,
		Name:     string(base.DailyDiskUsage) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *DailyDiskUsageCheckSuite) TearDownSuite() {
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

func (suite *DailyDiskUsageCheckSuite) TestGetHourlyDiskUsage() {
	err := suite.check.GetClient().HourlyDiskUsage.Create().
		SetTimestamp(time.Now()).
		SetDevice(uuid.NewString()).
		SetPeak(50.0).
		SetAvg(50.0).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create hourly disk usage.")

	querySet, err := suite.check.getHourlyDiskUsage(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get hourly disk usage.")
	assert.NotEmpty(suite.T(), querySet, "HourlyDiskUsage queryset should not be empty")
}

func (suite *DailyDiskUsageCheckSuite) TestDeleteHourlyDiskUsage() {
	err := suite.check.GetClient().HourlyDiskUsage.Create().
		SetTimestamp(time.Now().Add(-25 * time.Hour)).
		SetDevice(uuid.NewString()).
		SetPeak(50.0).
		SetAvg(50.0).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create hourly disk usage.")

	err = suite.check.deleteHourlyDiskUsage(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to delete hourly disk usage.")
}

func (suite *DailyDiskUsageCheckSuite) commitFailingCheck() *Check {
	return NewCheck(&base.CheckArgs{
		Type:     base.DailyDiskUsage,
		Name:     string(base.DailyDiskUsage) + "_" + uuid.NewString(),
		Interval: time.Second,
		Buffer:   base.NewCheckBuffer(10),
		Client:   dbtest.CommitFailingClient(suite.T(), dbFileName),
	}).(*Check)
}

func (suite *DailyDiskUsageCheckSuite) TestDeleteHourlyDiskUsageReturnsCommitError() {
	old := time.Now().Add(-25 * time.Hour)
	suite.Require().NoError(suite.client.HourlyDiskUsage.Create().SetTimestamp(old).SetDevice(uuid.NewString()).SetPeak(1).SetAvg(1).SetTotal(1).SetFree(1).SetUsed(1).Exec(suite.ctx))

	err := suite.commitFailingCheck().deleteHourlyDiskUsage(suite.ctx)

	suite.ErrorIs(err, dbtest.ErrCommitFailed)
	kept, err := suite.client.HourlyDiskUsage.Query().Where(hourlydiskusage.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(kept, "the failed commit must not delete the row")
}

func TestDailyDiskUsageCheckSuite(t *testing.T) {
	suite.Run(t, new(DailyDiskUsageCheckSuite))
}
