package cpu

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

var dbFileName = "cpu.db"

type CPUCheckSuite struct {
	suite.Suite
	client *ent.Client
	check  *Check
	ctx    context.Context
}

func (suite *CPUCheckSuite) SetupSuite() {
	suite.client = db.InitTestDB(dbFileName)
	buffer := base.NewCheckBuffer(10)
	args := &base.CheckArgs{
		Type:     base.CPU,
		Name:     string(base.CPU) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *CPUCheckSuite) TearDownSuite() {
	err := os.Remove(dbFileName)
	suite.Require().NoError(err, "failed to delete test db file")
}

func (suite *CPUCheckSuite) TestCollectCPUUsage() {
	usage, err := suite.check.collectCPUUsage()

	assert.NoError(suite.T(), err, "Failed to get cpu usage.")
	assert.GreaterOrEqual(suite.T(), usage, 0.0, "CPU usage should be non-negative.")
	assert.LessOrEqual(suite.T(), usage, 100.0, "CPU usage should not exceed 100%.")
}

func (suite *CPUCheckSuite) TestSaveCPUUsage() {
	data := base.CheckResult{
		Timestamp: time.Now(),
		Usage:     50.0,
	}

	err := suite.check.saveCPUUsage(data, suite.ctx)

	assert.NoError(suite.T(), err, "Failed to save cpu usage.")
}

func TestCPUCheckSuite(t *testing.T) {
	suite.Run(t, new(CPUCheckSuite))
}
