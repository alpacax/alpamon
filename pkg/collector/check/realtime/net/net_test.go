package net

import (
	"context"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/db"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var dbFileName = "net.db"

type NetCheckSuite struct {
	suite.Suite
	client       *ent.Client
	collectCheck *CollectCheck
	sendCheck    *SendCheck
	ctx          context.Context
}

func (suite *NetCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	collect_args := &base.CheckArgs{
		Type:     base.NetCollector,
		Name:     string(base.NetCollector) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	send_args := &base.CheckArgs{
		Type:     base.Net,
		Name:     string(base.Net) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.collectCheck = NewCheck(collect_args).(*CollectCheck)
	suite.sendCheck = NewCheck(send_args).(*SendCheck)
	suite.ctx = context.Background()
}

func (suite *NetCheckSuite) TearDownSuite() {
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

func (suite *NetCheckSuite) TestCollectIOCounters() {
	ioCounters, err := suite.collectCheck.collectIOCounters()
	assert.NoError(suite.T(), err, "Failed to get network IO.")
	assert.NotEmpty(suite.T(), ioCounters, "Network IO should not be empty")
}

func (suite *NetCheckSuite) TestCollectInterfaces() {
	interfaces, err := suite.collectCheck.collectInterfaces()
	assert.NoError(suite.T(), err, "Failed to get interfaces.")
	assert.NotEmpty(suite.T(), interfaces, "Interfaces should not be empty")
}

func (suite *NetCheckSuite) TestSaveTraffic() {
	ioCounters, interfaces, err := suite.collectCheck.collectTraffic()
	assert.NoError(suite.T(), err, "Failed to get traffic.")
	assert.NotEmpty(suite.T(), ioCounters, "Network IO should not be empty")
	assert.NotEmpty(suite.T(), interfaces, "Interfaces should not be empty")

	data := suite.collectCheck.parseTraffic(ioCounters, interfaces)

	err = suite.collectCheck.saveTraffic(data, suite.ctx)
	assert.NoError(suite.T(), err, "Failed to save traffic.")
}

func (suite *NetCheckSuite) TestGetTraffic() {
	err := suite.sendCheck.GetClient().Traffic.Create().
		SetTimestamp(time.Now()).
		SetName(uuid.NewString()).
		SetInputPps(rand.Float64()).
		SetInputBps(rand.Float64()).
		SetOutputPps(rand.Float64()).
		SetOutputBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create traffic.")

	staleName := "stale-" + uuid.NewString()
	err = suite.sendCheck.GetClient().Traffic.Create().
		SetTimestamp(time.Now().Add(-2 * time.Second)).
		SetName(staleName).
		SetInputPps(rand.Float64()).
		SetInputBps(rand.Float64()).
		SetOutputPps(rand.Float64()).
		SetOutputBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create stale traffic.")

	querySet, err := suite.sendCheck.getTraffic(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get traffic queryset.")
	assert.NotEmpty(suite.T(), querySet, "Traffic queryset should not be empty")

	for _, row := range querySet {
		assert.NotEqual(suite.T(), staleName, row.Name, "Traffic queryset should exclude rows outside the interval window")
	}
}

func TestNetCheckSuite(t *testing.T) {
	suite.Run(t, new(NetCheckSuite))
}
