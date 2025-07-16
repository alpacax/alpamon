package utils

import (
	"regexp"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/net"
)

var (
	virtualFileSystems = map[string]bool{
		"tmpfs":       true,
		"devtmpfs":    true,
		"proc":        true,
		"sysfs":       true,
		"cgroup":      true,
		"cgroup2":     true,
		"overlay":     true,
		"autofs":      true,
		"devfs":       true,
		"securityfs":  true,
		"fusectl":     true,
		"hugetlbfs":   true,
		"debugfs":     true,
		"pstore":      true,
		"tracefs":     true,
		"devpts":      true,
		"mqueue":      true,
		"bpf":         true,
		"configfs":    true,
		"binfmt_misc": true,
	}
	virtualMountpoints = map[string]bool{
		"/sys":  true,
		"/proc": true,
		"/dev":  true,
	}
	virtualMountPointPattern = "^/(sys|proc|run|dev/)"
	virtualInterfaceFlags    = map[string]bool{
		"flagloopback":     true,
		"flagpointtopoint": true,
	}
	loopFileSystemPrefix = "/dev/loop"
	virtaulDiskPattern   = regexp.MustCompile(`^(loop|ram|fd|sr|zram)\d*$`)
	nvmeDiskPattern      = regexp.MustCompile(`^(nvme\d+n\d+)(p\d+)?$`)
	scsiDiskPattern      = regexp.MustCompile(`^([a-z]+)(\d+)?$`)
	mmcDiskPattern       = regexp.MustCompile(`^(mmcblk\d+)(p\d+)?$`)
	lvmDiskPattern       = regexp.MustCompile(`^(dm-\d+)$`)
	macDiskPattern       = regexp.MustCompile(`^(disk\d+)(s\d+)?$`)
	VirtualIfacePattern  = regexp.MustCompile(`^(lo|docker|veth|br-|virbr|vmnet|tap|tun|wg|zt|tailscale|enp0s|cni)`)
)

func CalculateNetworkBps(current net.IOCountersStat, last net.IOCountersStat, interval time.Duration) (inputBps float64, outputBps float64) {
	if interval == 0 {
		return 0, 0
	}

	inputBytesDiff := float64(current.BytesRecv - last.BytesRecv)
	outputBytesDiff := float64(current.BytesSent - last.BytesSent)
	seconds := interval.Seconds()

	inputBps = (inputBytesDiff * 8) / seconds
	outputBps = (outputBytesDiff * 8) / seconds

	return inputBps, outputBps
}

func CalculateNetworkPps(current net.IOCountersStat, last net.IOCountersStat, interval time.Duration) (inputPps float64, outputPps float64) {
	if interval == 0 {
		return 0, 0
	}

	inputPktsDiff := float64(current.PacketsRecv - last.PacketsRecv)
	outputPktsDiff := float64(current.PacketsSent - last.PacketsSent)
	seconds := interval.Seconds()

	inputPps = inputPktsDiff / seconds
	outputPps = outputPktsDiff / seconds

	return inputPps, outputPps
}

func CalculateDiskIOBps(current disk.IOCountersStat, last disk.IOCountersStat, interval time.Duration) (readBps float64, writeBps float64) {
	if interval == 0 {
		return 0, 0
	}

	readBytesDiff := float64(current.ReadBytes - last.ReadBytes)
	writeBytesDiff := float64(current.WriteBytes - last.WriteBytes)
	seconds := interval.Seconds()

	readBps = readBytesDiff / seconds
	writeBps = writeBytesDiff / seconds

	return readBps, writeBps
}

func IsVirtualFileSystem(device string, fstype string, mountPoint string) bool {
	if strings.HasPrefix(device, loopFileSystemPrefix) {
		return true
	}

	matched, _ := regexp.MatchString(virtualMountPointPattern, mountPoint)
	if matched {
		return true
	}

	if virtualFileSystems[fstype] {
		return true
	}

	if virtualMountpoints[mountPoint] {
		return true
	}

	return false
}

func IsVirtualDisk(name string) bool {
	return virtaulDiskPattern.MatchString(name)
}

func ParseDiskName(device string) string {
	device = strings.TrimPrefix(device, "/dev/")

	re := regexp.MustCompile(`^[a-zA-Z]+`)
	if match := re.FindString(device); match != "" {
		return match
	}

	for i := len(device) - 1; i >= 0; i-- {
		if device[i] < '0' || device[i] > '9' {
			return device[:i+1]
		}
	}

	return device
}

func GetDiskBaseName(name string) string {
	switch {
	case strings.HasPrefix(name, "nvme"):
		if m := nvmeDiskPattern.FindStringSubmatch(name); len(m) >= 2 {
			return m[1]
		}
	case strings.HasPrefix(name, "mmcb"):
		if m := mmcDiskPattern.FindStringSubmatch(name); len(m) >= 2 {
			return m[1]
		}
	case strings.HasPrefix(name, "disk"):
		if m := macDiskPattern.FindStringSubmatch(name); len(m) >= 2 {
			return m[1]
		}
	case strings.HasPrefix(name, "dm-"):
		if m := lvmDiskPattern.FindStringSubmatch(name); len(m) >= 2 {
			return m[1]
		}
	default:
		if m := scsiDiskPattern.FindStringSubmatch(name); len(m) >= 2 {
			return m[1]
		}
	}

	return name
}

func FilterVirtualInterface(ifaces net.InterfaceStatList) map[string]net.InterfaceStat {
	interfaces := make(map[string]net.InterfaceStat)
	for _, iface := range ifaces {
		if iface.HardwareAddr == "" {
			continue
		}

		if VirtualIfacePattern.MatchString(iface.Name) {
			continue
		}

		isVirtualFlag := false
		for _, flag := range iface.Flags {
			if virtualInterfaceFlags[strings.ToLower(flag)] {
				isVirtualFlag = true
				break
			}
		}

		if isVirtualFlag {
			continue
		}

		interfaces[iface.Name] = iface
	}

	return interfaces
}
