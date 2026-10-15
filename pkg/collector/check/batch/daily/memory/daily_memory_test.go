package memory

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/testutil/dbtest"
	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/db"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/hourlymemoryusage"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var dbFileName = "daily_memory.db"

type DailyMemoryUsageCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *DailyMemoryUsageCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	suite.check = newCheck(suite.client)
	suite.ctx = context.Background()
}

func (suite *DailyMemoryUsageCheckSuite) TearDownSuite() {
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

func (suite *DailyMemoryUsageCheckSuite) TestGetHourlyMemoryUsage() {
	err := suite.check.GetClient().HourlyMemoryUsage.Create().
		SetTimestamp(time.Now()).
		SetPeak(50.0).
		SetAvg(50.0).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create hourly memory usage.")

	querySet, err := suite.check.getHourlyMemoryUsage(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get hourly memory usage.")
	assert.NotEmpty(suite.T(), querySet, "HouryMemoryUsage queryset should not be empty")
}

func (suite *DailyMemoryUsageCheckSuite) TestDeleteHourlyMemoryUsage() {
	err := suite.check.GetClient().HourlyMemoryUsage.Create().
		SetTimestamp(time.Now().Add(-25 * time.Hour)).
		SetPeak(50.0).
		SetAvg(50.0).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create hourly memory usage.")

	err = suite.check.deleteHourlyMemoryUsage(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to delete hourly memory usage.")
}

func newCheck(client *ent.Client) *Check {
	return NewCheck(&base.CheckArgs{
		Type:     base.DailyMemUsage,
		Name:     string(base.DailyMemUsage) + "_" + uuid.NewString(),
		Interval: time.Second,
		Buffer:   base.NewCheckBuffer(10),
		Client:   client,
	}).(*Check)
}

func (suite *DailyMemoryUsageCheckSuite) commitFailingCheck() *Check {
	return newCheck(dbtest.CommitFailingClient(suite.T(), dbFileName))
}

func (suite *DailyMemoryUsageCheckSuite) TestDeleteHourlyMemoryUsageReturnsCommitError() {
	old := time.Now().Add(-25 * time.Hour)
	suite.Require().NoError(suite.client.HourlyMemoryUsage.Create().SetTimestamp(old).SetPeak(1).SetAvg(1).Exec(suite.ctx))

	err := suite.commitFailingCheck().deleteHourlyMemoryUsage(suite.ctx)

	suite.ErrorIs(err, dbtest.ErrCommitFailed)
	kept, err := suite.client.HourlyMemoryUsage.Query().Where(hourlymemoryusage.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(kept, "the failed commit must not delete the row")
}

func TestDailyMemoryUsageCheckSuite(t *testing.T) {
	suite.Run(t, new(DailyMemoryUsageCheckSuite))
}
