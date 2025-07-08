package usage

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

var dbFileName = "hourly_disk_usage.db"

type HourlyDiskUsageCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *HourlyDiskUsageCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.HOURLY_DISK_USAGE,
		Name:     string(base.HOURLY_DISK_USAGE) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *HourlyDiskUsageCheckSuite) TearDownSuite() {
	err := os.Remove(dbFileName)
	suite.Require().NoError(err, "failed to delete test db file")
}

func (suite *HourlyDiskUsageCheckSuite) TestGetDiskUsage() {
	err := suite.check.GetClient().DiskUsage.Create().
		SetTimestamp(time.Now()).
		SetDevice(uuid.NewString()).
		SetUsage(rand.Float64()).
		SetTotal(int64(rand.Int())).
		SetFree(int64(rand.Int())).
		SetUsed(int64(rand.Int())).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create disk usage.")

	querySet, err := suite.check.getDiskUsage(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to get disk usage.")
	assert.NotEmpty(suite.T(), querySet, "Disk usage queryset should not be empty")
}

func (suite *HourlyDiskUsageCheckSuite) TestSaveHourlyDiskUsage() {
	data := []base.CheckResult{
		{
			Timestamp: time.Now(),
			Device:    uuid.NewString(),
			Peak:      50.0,
			Avg:       50.0,
		},
		{
			Timestamp: time.Now(),
			Device:    uuid.NewString(),
			Peak:      50.0,
			Avg:       50.0,
		},
	}

	err := suite.check.saveHourlyDiskUsage(data, suite.ctx)
	assert.NoError(suite.T(), err, "Failed to save hourly disk usage.")
}

func (suite *HourlyDiskUsageCheckSuite) TestDeleteDiskUsage() {
	err := suite.check.GetClient().DiskUsage.Create().
		SetTimestamp(time.Now().Add(-2 * time.Hour)).
		SetDevice(uuid.NewString()).
		SetUsage(rand.Float64()).
		SetTotal(int64(rand.Int())).
		SetFree(int64(rand.Int())).
		SetUsed(int64(rand.Int())).Exec(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to create disk usage.")

	err = suite.check.deleteDiskUsage(suite.ctx)
	assert.NoError(suite.T(), err, "Failed to delete disk usage.")
}

func TestHourlyDiskUsageCheckSuite(t *testing.T) {
	suite.Run(t, new(HourlyDiskUsageCheckSuite))
}
