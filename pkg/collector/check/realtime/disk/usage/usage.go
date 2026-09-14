package diskusage

import (
	"context"
	"runtime"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/shirou/gopsutil/v4/disk"
)

// dataDirFunc resolves the directory holding alpamon's own data (the SQLite
// metrics DB and agent state). It is a package-level var rather than a direct
// utils.DataDir() call so tests can point it at a fixture path without
// touching the filesystem.
var dataDirFunc = utils.DataDir

// listPartitions retrieves the host's mounted partitions. It is a
// package-level var, like dataDirFunc, so tests can inject a fixture
// partition list instead of depending on the real host/container mounts,
// which vary by environment (e.g. a container's root is commonly an
// overlay mount that isPhysicalDevice/IsVirtualFileSystem filter out).
var listPartitions = disk.Partitions

type Check struct {
	base.BaseCheck
}

func NewCheck(args *base.CheckArgs) base.CheckStrategy {
	return &Check{
		BaseCheck: base.NewBaseCheck(args),
	}
}

func (c *Check) Execute(ctx context.Context) error {
	metric, err := c.collectAndSaveDiskUsage(ctx)
	if err != nil {
		return err
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	if len(metric.Data) == 0 {
		return nil
	}

	buffer := c.GetBuffer()
	buffer.SuccessQueue <- metric

	return nil
}

func (c *Check) collectAndSaveDiskUsage(ctx context.Context) (base.MetricData, error) {
	partitions, err := c.collectDiskPartitions()
	if err != nil {
		return base.MetricData{}, err
	}

	data := c.parseDiskUsage(partitions)
	if len(data) == 0 {
		return base.MetricData{}, nil
	}

	metric := base.MetricData{
		Type: base.DiskUsage,
		Data: data,
	}

	err = c.saveDiskUsage(data, ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) parseDiskUsage(partitions []disk.PartitionStat) []base.CheckResult {
	var data []base.CheckResult
	seen := make(map[string]bool)

	// Resolve the device that owns alpamon's data directory before
	// deduplicating by device: the mountpoint that matches may not be the
	// first mountpoint seen for that device, so the owning device has to be
	// computed from the full partition list, not from the entry being built.
	agentVolumeDevice := findAgentVolumeDevice(partitions, dataDirFunc())

	for _, partition := range partitions {
		if seen[partition.Device] {
			continue
		}
		seen[partition.Device] = true

		usage, err := c.collectDiskUsage(partition.Mountpoint)
		if err == nil {
			data = append(data, base.CheckResult{
				Timestamp:   time.Now(),
				Device:      partition.Device,
				Usage:       usage.UsedPercent,
				Total:       usage.Total,
				Free:        usage.Free,
				Used:        usage.Used,
				AgentVolume: agentVolumeDevice != "" && partition.Device == agentVolumeDevice,
			})
		}
	}

	return data
}

// findAgentVolumeDevice returns the device backing the partition whose
// mountpoint is the longest path-prefix match of dataDir, i.e. the volume
// alpamon's own data lives on. It returns "" when no partition mountpoint
// contains dataDir.
func findAgentVolumeDevice(partitions []disk.PartitionStat, dataDir string) string {
	var device string
	bestLen := -1
	for _, partition := range partitions {
		if !mountpointOwns(partition.Mountpoint, dataDir) {
			continue
		}
		if l := len(partition.Mountpoint); l > bestLen {
			bestLen = l
			device = partition.Device
		}
	}

	return device
}

// mountpointOwns reports whether mountpoint is a path-boundary-respecting
// prefix of dir, e.g. "/var" matches "/var/lib/alpamon" but not
// "/variable/alpamon". Separators are normalized rather than routed through
// path/filepath, since gopsutil reports native paths per OS ("/var" on
// Unix, "C:\" on Windows) and this lets a single implementation, and a
// single test file, cover both without a build tag. Windows volume paths
// are case-insensitive (a "C:\" mountpoint owns "c:\ProgramData\..." just
// as much as "C:\ProgramData\..."), so a drive-letter path folds case
// before comparing; POSIX paths, which are case-sensitive, are left alone.
func mountpointOwns(mountpoint, dir string) bool {
	if mountpoint == "" || dir == "" {
		return false
	}

	m := normalizeSeparators(mountpoint)
	d := normalizeSeparators(dir)
	if hasDriveLetter(m) || hasDriveLetter(d) {
		m = strings.ToUpper(m)
		d = strings.ToUpper(d)
	}
	if m == d {
		return true
	}
	if m == "/" {
		return strings.HasPrefix(d, "/")
	}

	return strings.HasPrefix(d, m+"/")
}

func normalizeSeparators(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}

	return p
}

// hasDriveLetter reports whether p starts with a Windows drive letter
// ("C:", "d:", ...) once separators are normalized to "/".
func hasDriveLetter(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	c := p[0]

	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func (c *Check) collectDiskPartitions() ([]disk.PartitionStat, error) {
	partitions, err := listPartitions(true)
	if err != nil {
		return nil, err
	}

	var filteredPartitions []disk.PartitionStat
	for _, partition := range partitions {
		if utils.IsVirtualFileSystem(partition.Device, partition.Fstype, partition.Mountpoint) {
			continue
		}

		if isPhysicalDevice(partition) {
			filteredPartitions = append(filteredPartitions, partition)
		}
	}

	return filteredPartitions, nil
}

// isPhysicalDevice filters gopsutil PartitionStat entries to what we
// consider a real, operator-relevant disk. The kernel-reported device
// name shape differs by OS, so the allowlist has to be platform-aware:
//
//   - Linux / macOS: physical devices live under /dev (e.g. /dev/sda,
//     /dev/nvme0n1p1, /dev/disk1s1). The /dev prefix keeps loop, tmpfs,
//     and overlay entries out in case IsVirtualFileSystem missed one.
//   - Windows: gopsutil reports the drive root (C:\, D:\, ...) as the
//     device. There is no /dev equivalent; virtual entries are already
//     filtered by IsVirtualFileSystem, so every remaining partition is
//     a real volume we want to measure.
func isPhysicalDevice(p disk.PartitionStat) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	return strings.HasPrefix(p.Device, "/dev")
}

func (c *Check) collectDiskUsage(path string) (*disk.UsageStat, error) {
	usage, err := disk.Usage(path)
	if err != nil {
		return nil, err
	}

	return usage, nil
}

func (c *Check) saveDiskUsage(data []base.CheckResult, ctx context.Context) error {
	client := c.GetClient()
	err := client.DiskUsage.MapCreateBulk(data, func(q *ent.DiskUsageCreate, i int) {
		q.SetTimestamp(data[i].Timestamp).
			SetDevice(data[i].Device).
			SetUsage(data[i].Usage).
			SetTotal(int64(data[i].Total)).
			SetFree(int64(data[i].Free)).
			SetUsed(int64(data[i].Used))
	}).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}
