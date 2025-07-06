package diskusage

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

var dbFileName = "disk_usage.db"

type DiskUsageCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *DiskUsageCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.DISK_USAGE,
		Name:     string(base.DISK_USAGE) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *DiskUsageCheckSuite) TearDownSuite() {
	err := os.Remove(dbFileName)
	suite.Require().NoError(err, "failed to delete test db file")
}

func (suite *DiskUsageCheckSuite) TestCollectDiskPartitions() {
	partitions, err := suite.check.collectDiskPartitions()

	assert.NoError(suite.T(), err, "Failed to get disk partitions.")
	assert.NotEmpty(suite.T(), partitions, "Disk partitions should not be empty")
}

func (suite *DiskUsageCheckSuite) TestCollectDiskUsage() {
	partitions, err := suite.check.collectDiskPartitions()
	assert.NoError(suite.T(), err, "Failed to get disk partitions.")

	assert.NotEmpty(suite.T(), partitions, "Disk partitions should not be empty")
	for _, partition := range partitions {
		usage, err := suite.check.collectDiskUsage(partition.Mountpoint)
		assert.NoError(suite.T(), err, "Failed to get disk usage.")
		assert.GreaterOrEqual(suite.T(), usage.UsedPercent, 0.0, "Disk usage should be non-negative.")
		assert.LessOrEqual(suite.T(), usage.UsedPercent, 100.0, "Disk usage should not exceed 100%.")
	}
}

func (suite *DiskUsageCheckSuite) TestSaveDiskUsage() {
	partitions, err := suite.check.collectDiskPartitions()
	assert.NoError(suite.T(), err, "Failed to get disk partitions.")

	err = suite.check.saveDiskUsage(suite.check.parseDiskUsage(partitions), suite.ctx)
	assert.NoError(suite.T(), err, "Failed to save disk usage.")
}

func TestDiskUsageCheckSuite(t *testing.T) {
	suite.Run(t, new(DiskUsageCheckSuite))
}
