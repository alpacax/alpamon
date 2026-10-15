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
	suite.check = newCheck(suite.client)
	suite.ctx = context.Background()
}

func (suite *DailyNetCheckSuite) TearDownSuite() {
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

func newCheck(client *ent.Client) *Check {
	return NewCheck(&base.CheckArgs{
		Type:     base.DailyNet,
		Name:     string(base.DailyNet) + "_" + uuid.NewString(),
		Interval: time.Second,
		Buffer:   base.NewCheckBuffer(10),
		Client:   client,
	}).(*Check)
}

func (suite *DailyNetCheckSuite) commitFailingCheck() *Check {
	return newCheck(dbtest.CommitFailingClient(suite.T(), dbFileName))
}

func (suite *DailyNetCheckSuite) TestDeleteHourlyTrafficReturnsCommitError() {
	old := time.Now().Add(-25 * time.Hour)
	suite.Require().NoError(suite.client.HourlyTraffic.Create().SetTimestamp(old).SetName(uuid.NewString()).SetPeakInputPps(1).SetPeakInputBps(1).SetPeakOutputPps(1).SetPeakOutputBps(1).SetAvgInputPps(1).SetAvgInputBps(1).SetAvgOutputPps(1).SetAvgOutputBps(1).Exec(suite.ctx))

	err := suite.commitFailingCheck().deleteHourlyTraffic(suite.ctx)

	suite.ErrorIs(err, dbtest.ErrCommitFailed)
	kept, err := suite.client.HourlyTraffic.Query().Where(hourlytraffic.TimestampEQ(old)).Exist(suite.ctx)
	suite.Require().NoError(err)
	suite.True(kept, "the failed commit must not delete the row")
}

func TestDailyNetCheckSuite(t *testing.T) {
	suite.Run(t, new(DailyNetCheckSuite))
}
