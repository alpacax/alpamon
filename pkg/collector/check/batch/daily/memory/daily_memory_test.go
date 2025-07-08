package memory

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

var dbFileName = "daily_memory.db"

type DailyMemoryUsageCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *DailyMemoryUsageCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.DAILY_MEM_USAGE,
		Name:     string(base.DAILY_MEM_USAGE) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *DailyMemoryUsageCheckSuite) TearDownSuite() {
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

func TestDailyMemoryUsageCheckSuite(t *testing.T) {
	suite.Run(t, new(DailyMemoryUsageCheckSuite))
}
