package cpu

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
	"github.com/alpacax/alpamon/v2/pkg/db/ent/cpu"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/hourlycpuusage"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var dbFileName = "hourly_cpu.db"

type HourlyCPUUsageCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *HourlyCPUUsageCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.HourlyCPUUsage,
		Name:     string(base.HourlyCPUUsage) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *HourlyCPUUsageCheckSuite) TearDownSuite() {
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

func (suite *HourlyCPUUsageCheckSuite) TestGetCPU() {
	err := suite.check.GetClient().CPU.Create().
		SetTimestamp(time.Now()).
		SetUsage(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create cpu usage.")

	querySet, err := suite.check.getCPU(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get cpu usage.")
	assert.NotEmpty(suite.T(), querySet, "CPU queryset should not be empty")
}

func (suite *HourlyCPUUsageCheckSuite) TestSaveHourlyCPUUsage() {
	data := base.CheckResult{
		Timestamp: time.Now(),
		Peak:      50.0,
		Avg:       50.0,
	}

	err := suite.check.saveHourlyCPUUsage(data, suite.ctx)
	assert.NoError(suite.T(), err, "Failed to save hourly cpu usage.")
}

func (suite *HourlyCPUUsageCheckSuite) TestDeleteCPU() {
	err := suite.check.GetClient().CPU.Create().
		SetTimestamp(time.Now().Add(-2 * time.Hour)).
		SetUsage(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create cpu usage.")

	err = deleteCPU(suite.ctx, suite.client.CPU)
	assert.NoError(suite.T(), err, "Failed to delete cpu usage.")
}

func (suite *HourlyCPUUsageCheckSuite) commitFailingCheck() *Check {
	return NewCheck(&base.CheckArgs{
		Type:     base.HourlyCPUUsage,
		Name:     string(base.HourlyCPUUsage) + "_" + uuid.NewString(),
		Interval: time.Second,
		Buffer:   base.NewCheckBuffer(10),
		Client:   testutil.CommitFailingClient(suite.T(), dbFileName),
	}).(*Check)
}

func (suite *HourlyCPUUsageCheckSuite) TestSaveHourlyCPUUsageReturnsCommitErrorAndKeepsRawRows() {
	old := time.Now().Add(-2 * time.Hour)
	suite.Require().NoError(suite.client.CPU.Create().SetTimestamp(old).SetUsage(1).Exec(suite.ctx))
	ts := time.Now().Add(-42 * time.Minute)
	data := base.CheckResult{Timestamp: ts, Peak: 50.0, Avg: 50.0}

	err := suite.commitFailingCheck().saveHourlyCPUUsage(data, suite.ctx)

	suite.ErrorIs(err, testutil.ErrCommitFailed)
	stored, err := suite.client.HourlyCPUUsage.Query().Where(hourlycpuusage.TimestampEQ(ts)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.False(stored, "the failed commit must not store the hourly row")
	kept, err := suite.client.CPU.Query().Where(cpu.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(kept, "the failed commit must not delete the raw row")
}

func (suite *HourlyCPUUsageCheckSuite) TestSaveHourlyCPUUsageDeletesOldRawRows() {
	old := time.Now().Add(-2 * time.Hour)
	suite.Require().NoError(suite.client.CPU.Create().SetTimestamp(old).SetUsage(1).Exec(suite.ctx))
	ts := time.Now().Add(-41 * time.Minute)
	data := base.CheckResult{Timestamp: ts, Peak: 50.0, Avg: 50.0}

	err := suite.check.saveHourlyCPUUsage(data, suite.ctx)

	suite.Require().NoError(err)
	stored, err := suite.client.HourlyCPUUsage.Query().Where(hourlycpuusage.TimestampEQ(ts)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(stored)
	kept, err := suite.client.CPU.Query().Where(cpu.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.False(kept, "the save must delete raw rows older than an hour")
}

func TestHourlyCPUUsageCheckSuite(t *testing.T) {
	suite.Run(t, new(HourlyCPUUsageCheckSuite))
}
