package memory

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
	"github.com/alpacax/alpamon/v2/pkg/db/ent/hourlymemoryusage"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var dbFileName = "hourly_memory.db"

type HourlyMemoryUsageCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *HourlyMemoryUsageCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.HourlyMemUsage,
		Name:     string(base.HourlyMemUsage) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *HourlyMemoryUsageCheckSuite) TearDownSuite() {
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

func (suite *HourlyMemoryUsageCheckSuite) TestGetMemory() {
	err := suite.check.GetClient().CPU.Create().
		SetTimestamp(time.Now()).
		SetUsage(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create memory usage.")

	querySet, err := suite.check.getMemory(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get memory usage.")
	assert.NotEmpty(suite.T(), querySet, "Memory queryset should not be empty")
}

func (suite *HourlyMemoryUsageCheckSuite) TestSaveMemoryPerHour() {
	data := base.CheckResult{
		Timestamp: time.Now(),
		Peak:      50.0,
		Avg:       50.0,
	}

	err := suite.check.saveHourlyMemoryUsage(data, suite.ctx)
	assert.NoError(suite.T(), err, "Failed to save memory usage per hour.")
}

func (suite *HourlyMemoryUsageCheckSuite) TestDeleteMemory() {
	err := suite.check.GetClient().Memory.Create().
		SetTimestamp(time.Now().Add(-2 * time.Hour)).
		SetUsage(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create memory usage.")

	err = deleteMemory(suite.ctx, suite.client.Memory)
	assert.NoError(suite.T(), err, "Failed to delete memory usage.")
}

func (suite *HourlyMemoryUsageCheckSuite) commitFailingCheck() *Check {
	return NewCheck(&base.CheckArgs{
		Type:     base.HourlyMemUsage,
		Name:     string(base.HourlyMemUsage) + "_" + uuid.NewString(),
		Interval: time.Second,
		Buffer:   base.NewCheckBuffer(10),
		Client:   dbtest.CommitFailingClient(suite.T(), dbFileName),
	}).(*Check)
}

func (suite *HourlyMemoryUsageCheckSuite) TestSaveHourlyMemoryUsageReturnsCommitErrorAndKeepsRawRows() {
	old := time.Now().Add(-2 * time.Hour)
	suite.Require().NoError(suite.client.Memory.Create().SetTimestamp(old).SetUsage(1).Exec(suite.ctx))
	ts := time.Now().Add(-42 * time.Minute)
	data := base.CheckResult{Timestamp: ts, Peak: 50.0, Avg: 50.0}

	err := suite.commitFailingCheck().saveHourlyMemoryUsage(data, suite.ctx)

	suite.ErrorIs(err, dbtest.ErrCommitFailed)
	stored, err := suite.client.HourlyMemoryUsage.Query().Where(hourlymemoryusage.TimestampEQ(ts)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.False(stored, "the failed commit must not store the hourly row")
	kept, err := suite.client.Memory.Query().Where(memory.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(kept, "the failed commit must not delete the raw row")
}

func (suite *HourlyMemoryUsageCheckSuite) TestSaveHourlyMemoryUsageDeletesOldRawRows() {
	old := time.Now().Add(-2 * time.Hour)
	suite.Require().NoError(suite.client.Memory.Create().SetTimestamp(old).SetUsage(1).Exec(suite.ctx))
	ts := time.Now().Add(-41 * time.Minute)
	data := base.CheckResult{Timestamp: ts, Peak: 50.0, Avg: 50.0}

	err := suite.check.saveHourlyMemoryUsage(data, suite.ctx)

	suite.Require().NoError(err)
	stored, err := suite.client.HourlyMemoryUsage.Query().Where(hourlymemoryusage.TimestampEQ(ts)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(stored)
	kept, err := suite.client.Memory.Query().Where(memory.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.False(kept, "the save must delete raw rows older than an hour")
}

func TestHourlyMemoryCheckSuite(t *testing.T) {
	suite.Run(t, new(HourlyMemoryUsageCheckSuite))
}
