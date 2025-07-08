package cpu

import (
	"context"
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

var dbFileName = "daily_cpu.db"

type DailyCPUUsageCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *DailyCPUUsageCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.DAILY_CPU_USAGE,
		Name:     string(base.DAILY_CPU_USAGE) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *DailyCPUUsageCheckSuite) TearDownSuite() {
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

func TestDailyCPUUsageCheckSuite(t *testing.T) {
	suite.Run(t, new(DailyCPUUsageCheckSuite))
}
