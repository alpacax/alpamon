package cpu

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/testutil/dbtest"
	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/db"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/hourlycpuusage"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var dbFileName = "daily_cpu.db"

type DailyCPUUsageCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *DailyCPUUsageCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	suite.check = newCheck(suite.client)
	suite.ctx = context.Background()
}

func (suite *DailyCPUUsageCheckSuite) TearDownSuite() {
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

func (suite *DailyCPUUsageCheckSuite) TestGetHourlyCPUUsage() {
	err := suite.check.GetClient().HourlyCPUUsage.Create().
		SetTimestamp(time.Now()).
		SetPeak(50.0).
		SetAvg(50.0).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create hourly cpu usage.")

	querySet, err := suite.check.getHourlyCPUUsage(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get hourly cpu usage.")
	assert.NotEmpty(suite.T(), querySet, "HourlyCPUUsage queryset should not be empty")
}

func (suite *DailyCPUUsageCheckSuite) TestDeleteHourlyCPUUsage() {
	err := suite.check.GetClient().HourlyCPUUsage.Create().
		SetTimestamp(time.Now().Add(-25 * time.Hour)).
		SetPeak(50.0).
		SetAvg(50.0).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create hourly cpu usage.")

	err = suite.check.deleteHourlyCPUUsage(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to delete hourly cpu usage.")
}

func newCheck(client *ent.Client) *Check {
	return NewCheck(&base.CheckArgs{
		Type:     base.DailyCPUUsage,
		Name:     string(base.DailyCPUUsage) + "_" + uuid.NewString(),
		Interval: time.Second,
		Buffer:   base.NewCheckBuffer(10),
		Client:   client,
	}).(*Check)
}

func (suite *DailyCPUUsageCheckSuite) commitFailingCheck() *Check {
	return newCheck(dbtest.CommitFailingClient(suite.T(), dbFileName))
}

func (suite *DailyCPUUsageCheckSuite) TestDeleteHourlyCPUUsageReturnsCommitError() {
	old := time.Now().Add(-25 * time.Hour)
	suite.Require().NoError(suite.client.HourlyCPUUsage.Create().SetTimestamp(old).SetPeak(1).SetAvg(1).Exec(suite.ctx))

	err := suite.commitFailingCheck().deleteHourlyCPUUsage(suite.ctx)

	suite.ErrorIs(err, dbtest.ErrCommitFailed)
	kept, err := suite.client.HourlyCPUUsage.Query().Where(hourlycpuusage.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(kept, "the failed commit must not delete the row")
}

func TestDailyCPUUsageCheckSuite(t *testing.T) {
	suite.Run(t, new(DailyCPUUsageCheckSuite))
}
