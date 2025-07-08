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

var dbFileName = "hourly_io.db"

type HourlyDiskIOCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *HourlyDiskIOCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.HOURLY_DISK_IO,
		Name:     string(base.HOURLY_DISK_IO) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *HourlyDiskIOCheckSuite) TearDownSuite() {
	err := os.Remove(dbFileName)
	suite.Require().NoError(err, "failed to delete test db file")
}

func (suite *HourlyDiskIOCheckSuite) TestGetDiskIO() {
	err := suite.check.GetClient().DiskIO.Create().
		SetTimestamp(time.Now()).
		SetDevice(uuid.NewString()).
		SetReadBps(rand.Float64()).
		SetWriteBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create disk io.")

	querySet, err := suite.check.getDiskIO(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get disk io.")
	assert.NotEmpty(suite.T(), querySet, "Disk io queryset should not be empty")
}

func (suite *HourlyDiskIOCheckSuite) TestSaveHourlyDiskIO() {
	data := []base.CheckResult{
		{
			Timestamp:    time.Now(),
			Device:       uuid.NewString(),
			PeakWriteBps: rand.Float64(),
			PeakReadBps:  rand.Float64(),
			AvgWriteBps:  rand.Float64(),
			AvgReadBps:   rand.Float64(),
		},
		{
			Timestamp:    time.Now(),
			Device:       uuid.NewString(),
			PeakWriteBps: rand.Float64(),
			PeakReadBps:  rand.Float64(),
			AvgWriteBps:  rand.Float64(),
			AvgReadBps:   rand.Float64(),
		},
	}

	err := suite.check.saveHourlyDiskIO(data, suite.ctx)
	assert.NoError(suite.T(), err, "Failed to save hourly disk io.")
}

func (suite *HourlyDiskIOCheckSuite) TestDeleteDiskIO() {
	err := suite.check.GetClient().DiskIO.Create().
		SetTimestamp(time.Now().Add(-2 * time.Hour)).
		SetDevice(uuid.NewString()).
		SetReadBps(rand.Float64()).
		SetWriteBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create disk io.")

	err = suite.check.deleteDiskIO(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to delete disk io.")
}

func TestHourlyDiskIOCheckSuite(t *testing.T) {
	suite.Run(t, new(HourlyDiskIOCheckSuite))
}
