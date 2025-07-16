package io

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

var dbFileName = "daily_io.db"

type DailyDiskIOCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *DailyDiskIOCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.DAILY_DISK_IO,
		Name:     string(base.DAILY_DISK_IO) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *DailyDiskIOCheckSuite) TearDownSuite() {
	err := os.Remove(dbFileName)
	suite.Require().NoError(err, "failed to delete test db file")
}

func (suite *DailyDiskIOCheckSuite) TestGetHourlyDiskIO() {
	err := suite.check.GetClient().HourlyDiskIO.Create().
		SetTimestamp(time.Now()).
		SetDevice(uuid.NewString()).
		SetPeakReadBps(rand.Float64()).
		SetPeakWriteBps(rand.Float64()).
		SetAvgReadBps(rand.Float64()).
		SetAvgWriteBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create hourly disk io.")

	querySet, err := suite.check.getHourlyDiskIO(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get hourly disk io.")
	assert.NotEmpty(suite.T(), querySet, "HourlyDiskIO queryset should not be empty")
}

func (suite *DailyDiskIOCheckSuite) TestDeleteHourlyDiskIO() {
	err := suite.check.GetClient().HourlyDiskIO.Create().
		SetTimestamp(time.Now().Add(-25 * time.Hour)).
		SetDevice(uuid.NewString()).
		SetPeakReadBps(rand.Float64()).
		SetPeakWriteBps(rand.Float64()).
		SetAvgReadBps(rand.Float64()).
		SetAvgWriteBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create hourly disk io.")

	err = suite.check.deleteHourlyDiskIO(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to delete hourly disk io.")
}

func TestDailyDiskIOCheckSuite(t *testing.T) {
	suite.Run(t, new(DailyDiskIOCheckSuite))
}
