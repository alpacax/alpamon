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
		Type:     base.NET_COLLECTOR,
		Name:     string(base.NET_COLLECTOR) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	send_args := &base.CheckArgs{
		Type:     base.NET,
		Name:     string(base.NET) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.collectCheck = NewCheck(collect_args).(*CollectCheck)
	suite.sendCheck = NewCheck(send_args).(*SendCheck)
	suite.ctx = context.Background()
}

func (suite *NetCheckSuite) TearDownSuite() {
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

	querySet, err := suite.sendCheck.getTraffic(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get traffic queryset.")
	assert.NotEmpty(suite.T(), querySet, "Traffic queryset should not be empty")
}

func TestNetCheckSuite(t *testing.T) {
	suite.Run(t, new(NetCheckSuite))
}
