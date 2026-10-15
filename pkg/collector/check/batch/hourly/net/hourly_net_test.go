package net

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
	"github.com/alpacax/alpamon/v2/pkg/db/ent/hourlytraffic"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/traffic"
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
		Type:     base.HourlyNet,
		Name:     string(base.HourlyNet) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *HourlyNetCheckSuite) TearDownSuite() {
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

	err = deleteTraffic(suite.ctx, suite.client.Traffic)
	assert.NoError(suite.T(), err, "Failed to delete traffic.")
}

func (suite *HourlyNetCheckSuite) commitFailingCheck() *Check {
	return NewCheck(&base.CheckArgs{
		Type:     base.HourlyNet,
		Name:     string(base.HourlyNet) + "_" + uuid.NewString(),
		Interval: time.Second,
		Buffer:   base.NewCheckBuffer(10),
		Client:   dbtest.CommitFailingClient(suite.T(), dbFileName),
	}).(*Check)
}

func (suite *HourlyNetCheckSuite) TestSaveHourlyTrafficReturnsCommitErrorAndKeepsRawRows() {
	old := time.Now().Add(-2 * time.Hour)
	suite.Require().NoError(suite.client.Traffic.Create().SetTimestamp(old).SetName(uuid.NewString()).SetInputPps(1).SetInputBps(1).SetOutputPps(1).SetOutputBps(1).Exec(suite.ctx))
	ts := time.Now().Add(-42 * time.Minute)
	data := []base.CheckResult{{Timestamp: ts, Name: uuid.NewString()}}

	err := suite.commitFailingCheck().saveHourlyTraffic(data, suite.ctx)

	suite.ErrorIs(err, dbtest.ErrCommitFailed)
	stored, err := suite.client.HourlyTraffic.Query().Where(hourlytraffic.TimestampEQ(ts)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.False(stored, "the failed commit must not store the hourly row")
	kept, err := suite.client.Traffic.Query().Where(traffic.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(kept, "the failed commit must not delete the raw row")
}

func (suite *HourlyNetCheckSuite) TestSaveHourlyTrafficDeletesOldRawRows() {
	old := time.Now().Add(-2 * time.Hour)
	suite.Require().NoError(suite.client.Traffic.Create().SetTimestamp(old).SetName(uuid.NewString()).SetInputPps(1).SetInputBps(1).SetOutputPps(1).SetOutputBps(1).Exec(suite.ctx))
	ts := time.Now().Add(-41 * time.Minute)
	data := []base.CheckResult{{Timestamp: ts, Name: uuid.NewString()}}

	err := suite.check.saveHourlyTraffic(data, suite.ctx)

	suite.Require().NoError(err)
	stored, err := suite.client.HourlyTraffic.Query().Where(hourlytraffic.TimestampEQ(ts)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(stored)
	kept, err := suite.client.Traffic.Query().Where(traffic.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.False(kept, "the save must delete raw rows older than an hour")
}

func TestHourlyNetCheckSuite(t *testing.T) {
	suite.Run(t, new(HourlyNetCheckSuite))
}
