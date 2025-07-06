package diskio

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

var dbFileName = "io.db"

type DiskIOCheckSuite struct {
	suite.Suite
	client       *ent.Client
	collectCheck *CollectCheck
	sendCheck    *SendCheck
	ctx          context.Context
}

func (suite *DiskIOCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	collect_args := &base.CheckArgs{
		Type:     base.DISK_IO_COLLECTOR,
		Name:     string(base.DISK_IO_COLLECTOR) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	send_args := &base.CheckArgs{
		Type:     base.DISK_IO,
		Name:     string(base.DISK_IO) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.collectCheck = NewCheck(collect_args).(*CollectCheck)
	suite.sendCheck = NewCheck(send_args).(*SendCheck)
	suite.ctx = context.Background()
}

func (suite *DiskIOCheckSuite) TearDownSuite() {
	err := os.Remove(dbFileName)
	suite.Require().NoError(err, "failed to delete test db file")
}

func (suite *DiskIOCheckSuite) TestCollectDiskIO() {
	ioCounters, err := suite.collectCheck.collectDiskIO()
	assert.NoError(suite.T(), err, "Failed to get disk io.")

	assert.NotEmpty(suite.T(), ioCounters, "Disk IO should not be empty")
	for name, ioCounter := range ioCounters {
		assert.NotEmpty(suite.T(), name, "Device name should not be empty")
		assert.GreaterOrEqual(suite.T(), ioCounter.ReadBytes, uint64(0), "Read bytes should be non-negative.")
		assert.GreaterOrEqual(suite.T(), ioCounter.WriteBytes, uint64(0), "Write bytes should be non-negative.")
	}
}

func (suite *DiskIOCheckSuite) TestSaveDiskIO() {
	ioCounters, err := suite.collectCheck.collectDiskIO()
	assert.NoError(suite.T(), err, "Failed to get disk io.")

	data := suite.collectCheck.parseDiskIO(ioCounters)

	err = suite.collectCheck.saveDiskIO(data, suite.ctx)
	assert.NoError(suite.T(), err, "Failed to save cpu usage.")
}

func (suite *DiskIOCheckSuite) TestGetDiskIO() {
	err := suite.collectCheck.GetClient().DiskIO.Create().
		SetTimestamp(time.Now()).
		SetDevice(uuid.NewString()).
		SetReadBps(rand.Float64()).
		SetWriteBps(rand.Float64()).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create disk io.")

	querySet, err := suite.sendCheck.getDiskIO(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get disk io queryset.")
	assert.NotEmpty(suite.T(), querySet, "Disk IO queryset should not be empty")
}

func TestDiskIOCheckSuite(t *testing.T) {
	suite.Run(t, new(DiskIOCheckSuite))
}
