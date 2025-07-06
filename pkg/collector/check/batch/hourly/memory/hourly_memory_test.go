package memory

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
		Type:     base.HOURLY_MEM_USAGE,
		Name:     string(base.HOURLY_MEM_USAGE) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *HourlyMemoryUsageCheckSuite) TearDownSuite() {
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

	err = suite.check.deleteMemory(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to delete memory usage.")
}

func TestHourlyMemoryCheckSuite(t *testing.T) {
	suite.Run(t, new(HourlyMemoryUsageCheckSuite))
}
