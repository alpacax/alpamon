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

var dbFileName = "hourly_net.db"

type HourlyNetCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *HourlyNetCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.HOURLY_NET,
		Name:     string(base.HOURLY_NET) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *HourlyNetCheckSuite) TearDownSuite() {
	err := os.Remove(dbFileName)
	suite.Require().NoError(err, "failed to delete test db file")
}

func (suite *HourlyNetCheckSuite) TestGetTraffic() {
	err := suite.check.GetClient().Traffic.Create().
		SetTimestamp(time.Now()).
		SetName(uuid.NewString()).
		SetInputPps(rand.Float64()).
		SetInputBps(rand.Float64()).
		SetOutputPps(rand.Float64()).
		SetOutputBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create traffic.")

	querySet, err := suite.check.getTraffic(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get traffic.")
	assert.NotEmpty(suite.T(), querySet, "Traffic queryset should not be empty")
}

func (suite *HourlyNetCheckSuite) TestSaveHourlyTraffic() {
	data := []base.CheckResult{
		{
			Timestamp:     time.Now(),
			Name:          uuid.NewString(),
			PeakInputPps:  rand.Float64(),
			PeakInputBps:  rand.Float64(),
			AvgInputPps:   rand.Float64(),
			AvgInputBps:   rand.Float64(),
			PeakOutputPps: rand.Float64(),
			PeakOutputBps: rand.Float64(),
			AvgOutputPps:  rand.Float64(),
			AvgOutputBps:  rand.Float64(),
		},
		{
			Timestamp:     time.Now(),
			Name:          uuid.NewString(),
			PeakInputPps:  rand.Float64(),
			PeakInputBps:  rand.Float64(),
			AvgInputPps:   rand.Float64(),
			AvgInputBps:   rand.Float64(),
			PeakOutputPps: rand.Float64(),
			PeakOutputBps: rand.Float64(),
			AvgOutputPps:  rand.Float64(),
			AvgOutputBps:  rand.Float64(),
		},
	}

	err := suite.check.saveHourlyTraffic(data, suite.ctx)
	assert.NoError(suite.T(), err, "Failed to save houlry traffic.")
}

func (suite *HourlyNetCheckSuite) TestDeleteTraffic() {
	err := suite.check.GetClient().Traffic.Create().
		SetTimestamp(time.Now().Add(-2 * time.Hour)).
		SetName(uuid.NewString()).
		SetInputPps(rand.Float64()).
		SetInputBps(rand.Float64()).
		SetOutputPps(rand.Float64()).
		SetOutputBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create traffic.")

	err = suite.check.deleteTraffic(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to delete traffic.")
}

func TestHourlyNetCheckSuite(t *testing.T) {
	suite.Run(t, new(HourlyNetCheckSuite))
}
