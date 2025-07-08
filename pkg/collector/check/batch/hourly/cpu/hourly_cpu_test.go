package cpu

import (
	"context"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db"
	"github.com/alpacax/alpamon/pkg/db/ent"
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
		Type:     base.HOURLY_CPU_USAGE,
		Name:     string(base.HOURLY_CPU_USAGE) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *HourlyCPUUsageCheckSuite) TearDownSuite() {
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

	err = suite.check.deleteCPU(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to delete cpu usage.")
}

func TestHourlyCPUUsageCheckSuite(t *testing.T) {
	suite.Run(t, new(HourlyCPUUsageCheckSuite))
}
