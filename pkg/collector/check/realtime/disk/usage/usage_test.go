package diskusage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/db"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v4/disk"
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
		Type:     base.DiskUsage,
		Name:     string(base.DiskUsage) + "_" + uuid.NewString(),
		Interval: time.Duration(1 * time.Second),
		Buffer:   buffer,
		Client:   suite.client,
	}
	suite.check = NewCheck(args).(*Check)
	suite.ctx = context.Background()
}

func (suite *DiskUsageCheckSuite) TearDownSuite() {
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

// TestParseDiskUsageFlagsAgentVolume points dataDirFunc at the root mount,
// which every partition list collected on a live host contains, and checks
// that parseDiskUsage flags exactly the entry backing it.
func (suite *DiskUsageCheckSuite) TestParseDiskUsageFlagsAgentVolume() {
	partitions, err := suite.check.collectDiskPartitions()
	suite.Require().NoError(err, "Failed to get disk partitions.")
	suite.Require().NotEmpty(partitions, "Disk partitions should not be empty")

	original := dataDirFunc
	defer func() { dataDirFunc = original }()
	dataDirFunc = func() string { return "/" }

	data := suite.check.parseDiskUsage(partitions)
	suite.Require().NotEmpty(data)

	flagged := 0
	for _, entry := range data {
		if entry.AgentVolume {
			flagged++
		}
	}
	assert.Equal(suite.T(), 1, flagged, "exactly one entry should be flagged as the agent volume")
}

func TestDiskUsageCheckSuite(t *testing.T) {
	suite.Run(t, new(DiskUsageCheckSuite))
}

func TestMountpointOwns(t *testing.T) {
	tests := []struct {
		name       string
		mountpoint string
		dir        string
		want       bool
	}{
		{"root owns everything under it", "/", "/var/lib/alpamon", true},
		{"exact match", "/var/lib/alpamon", "/var/lib/alpamon", true},
		{"nested boundary respected", "/var", "/var/lib/alpamon", true},
		{"prefix without path boundary is rejected", "/var", "/variable/alpamon", false},
		{"disjoint tree", "/mnt/data", "/var/lib/alpamon", false},
		{"windows drive root", `C:\`, `C:\ProgramData\alpamon\data`, true},
		{"windows nested directory", `C:\ProgramData`, `C:\ProgramData\alpamon\data`, true},
		{"windows different drive", `D:\`, `C:\ProgramData\alpamon\data`, false},
		{"empty mountpoint", "", "/var/lib/alpamon", false},
		{"empty dir", "/var", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, mountpointOwns(tt.mountpoint, tt.dir))
		})
	}
}

func TestFindAgentVolumeDevice(t *testing.T) {
	t.Run("picks the longest matching mountpoint regardless of list order", func(t *testing.T) {
		partitions := []disk.PartitionStat{
			{Device: "/dev/sda1", Mountpoint: "/"},
			{Device: "/dev/sdb1", Mountpoint: "/var/lib"},
			{Device: "/dev/sdc1", Mountpoint: "/var"},
		}
		assert.Equal(t, "/dev/sdb1", findAgentVolumeDevice(partitions, "/var/lib/alpamon"))

		reordered := []disk.PartitionStat{
			{Device: "/dev/sdb1", Mountpoint: "/var/lib"},
			{Device: "/dev/sdc1", Mountpoint: "/var"},
			{Device: "/dev/sda1", Mountpoint: "/"},
		}
		assert.Equal(t, "/dev/sdb1", findAgentVolumeDevice(reordered, "/var/lib/alpamon"))
	})

	t.Run("no match returns empty device", func(t *testing.T) {
		partitions := []disk.PartitionStat{
			{Device: "/dev/sdc1", Mountpoint: "/var"},
		}
		assert.Empty(t, findAgentVolumeDevice(partitions, "/opt/alpamon"))
	})

	t.Run("windows-style paths", func(t *testing.T) {
		partitions := []disk.PartitionStat{
			{Device: "C:", Mountpoint: `C:\`},
			{Device: "D:", Mountpoint: `D:\Data`},
		}
		assert.Equal(t, "D:", findAgentVolumeDevice(partitions, `D:\Data\alpamon`))
		assert.Equal(t, "C:", findAgentVolumeDevice(partitions, `C:\ProgramData\alpamon\data`))
	})
}

// TestAgentVolumeSurvivesDeviceDedup proves the flag lands on the emitted
// entry even when the owning mountpoint is not the first one seen for its
// device: parseDiskUsage keeps only the first mountpoint per device, so the
// flag has to be resolved by device identity, not by which mountpoint
// matched.
func TestAgentVolumeSurvivesDeviceDedup(t *testing.T) {
	partitions := []disk.PartitionStat{
		{Device: "/dev/sda1", Mountpoint: "/data"},
		{Device: "/dev/sda1", Mountpoint: "/data/nested/alpamon"},
	}

	agentVolumeDevice := findAgentVolumeDevice(partitions, "/data/nested/alpamon/state")
	assert.Equal(t, "/dev/sda1", agentVolumeDevice)

	// Reproduce parseDiskUsage's device dedup: only the first-seen
	// mountpoint per device becomes an entry.
	seen := make(map[string]bool)
	var flaggedMountpoint string
	for _, partition := range partitions {
		if seen[partition.Device] {
			continue
		}
		seen[partition.Device] = true
		if agentVolumeDevice != "" && partition.Device == agentVolumeDevice {
			flaggedMountpoint = partition.Mountpoint
		}
	}

	assert.Equal(t, "/data", flaggedMountpoint, "the flag must land on the first-seen (emitted) mountpoint of the owning device")
}
