package net

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

var dbFileName = "daily_net.db"

type DailyNetCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *DailyNetCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.DAILY_NET,
		Name:     string(base.DAILY_NET) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *DailyNetCheckSuite) TearDownSuite() {
	err := os.Remove(dbFileName)
	suite.Require().NoError(err, "failed to delete test db file")
}

func (suite *DailyNetCheckSuite) TestGetHourlyTraffic() {
	err := suite.check.GetClient().HourlyTraffic.Create().
		SetTimestamp(time.Now()).
		SetName(uuid.NewString()).
		SetPeakInputPps(rand.Float64()).
		SetPeakInputBps(rand.Float64()).
		SetPeakOutputPps(rand.Float64()).
		SetPeakOutputBps(rand.Float64()).
		SetAvgInputPps(rand.Float64()).
		SetAvgInputBps(rand.Float64()).
		SetAvgOutputPps(rand.Float64()).
		SetAvgOutputBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create hourly traffic.")

	querySet, err := suite.check.getHourlyTraffic(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get hourly traffic.")
	assert.NotEmpty(suite.T(), querySet, "HourlyTraffic queryset should not be empty")
}

func (suite *DailyNetCheckSuite) TestDeleteHourlyTraffic() {
	err := suite.check.GetClient().HourlyTraffic.Create().
		SetTimestamp(time.Now().Add(-25 * time.Hour)).
		SetName(uuid.NewString()).
		SetPeakInputPps(rand.Float64()).
		SetPeakInputBps(rand.Float64()).
		SetPeakOutputPps(rand.Float64()).
		SetPeakOutputBps(rand.Float64()).
		SetAvgInputPps(rand.Float64()).
		SetAvgInputBps(rand.Float64()).
		SetAvgOutputPps(rand.Float64()).
		SetAvgOutputBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create hourly traffic.")

	err = suite.check.deleteHourlyTraffic(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to delete hourly traffic.")
}

func TestDailyNetCheckSuite(t *testing.T) {
	suite.Run(t, new(DailyNetCheckSuite))
}
