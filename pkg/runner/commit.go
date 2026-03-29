package runner

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/alpacax/alpamon/pkg/version"
	_ "github.com/glebarez/go-sqlite"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

const (
	commitURL       = "/api/servers/servers/-/commit/"
	eventURL        = "/api/events/events/"
	accessPolicyURL = "/api/servers/servers/-/access-policy/"
	syncCheckURL    = "/api/servers/servers/-/sync-check/"

	// maxCommitJitterSeconds is the upper bound (exclusive) for random commit
	// delay when uncommissioned servers register, distributing N simultaneous
	// IaC-provisioned commits over a 0-30 second window.
	maxCommitJitterSeconds = 31

	IFF_UP          = 1 << 0 // Interface is up
	IFF_LOOPBACK    = 1 << 3 // Loopback interface
	IFF_POINTOPOINT = 1 << 4 // Point-to-point link
	IFF_RUNNING     = 1 << 6 // Interface is running
)

var syncMutex sync.Mutex

// CommitAsync commits system information asynchronously
// Uses ContextManager for coordinated lifecycle management
func CommitAsync(session *scheduler.Session, commissioned bool, ctxManager *agent.ContextManager) {
	if commissioned {
		// Use a goroutine with delayed execution for commissioned systems
		go func() {
			// Get application-level context for shutdown coordination
			ctx := ctxManager.Root()

			// Wait for either timeout or shutdown signal
			select {
			case <-time.After(5 * time.Second):
				// Timeout occurred, proceed with sync
				SyncSystemInfo(session, nil)
			case <-ctx.Done():
				// Shutdown occurred before timeout, skip sync
				log.Debug().Msg("Skipping syncSystemInfo due to shutdown")
			}
		}()
	} else {
		go func() {
			ctx := ctxManager.Root()
			jitter := time.Duration(rand.IntN(maxCommitJitterSeconds)) * time.Second
			select {
			case <-time.After(jitter):
				CommitSystemInfo()
			case <-ctx.Done():
				log.Debug().Msg("Skipping commitSystemInfo due to shutdown")
			}
		}()
	}
}

func CommitSystemInfo() {
	log.Debug().Msg("Start committing system information.")

	data := collectData()

	scheduler.Rqueue.Put(commitURL, data, 80, time.Time{})
	scheduler.Rqueue.Post(eventURL, []byte(fmt.Sprintf(`{
		"reporter": "alpamon",
		"record": "committed",
		"description": "Committed system information. version: %s"}`, version.Version)), 80, time.Time{})

	// Sync firewall rules after committing system info
	// Skip if firewall functionality is disabled
	// Note: Full firewall sync is handled by FirewallHandler in executor package
	if utils.IsFirewallDisabled() {
		log.Debug().Msg("Skipping firewall sync - firewall functionality is disabled")
	} else {
		log.Debug().Msg("Firewall sync delegated to executor FirewallHandler")
	}

	log.Info().Msg("Completed committing system information.")
}

func SyncSystemInfo(session *scheduler.Session, keys []string) {
	log.Debug().Msg("Start system information synchronization.")

	syncMutex.Lock()
	defer syncMutex.Unlock()

	fullSync := len(keys) == 0

	// Warn about unknown keys from caller (e.g., info sync command).
	if !fullSync {
		for _, key := range keys {
			if key != "server" && key != "firewall" {
				if _, ok := syncerMap[key]; !ok {
					log.Warn().Str("key", key).Msg("Unknown sync key requested, ignoring.")
				}
			}
		}
	}

	// server is always synced unconditionally (not hashed).
	syncServerData(session)

	// Step 1: collect data and compute hashes for data categories.
	snap := collectSnapshot(keys)

	// Step 2 & 3: check hashes with server and sync changed categories.
	if !snap.empty() {
		for _, key := range syncRequiredKeys(session, snap) {
			data, exists := snap.data[key]
			if !exists {
				log.Warn().Str("key", key).Msg("Server requested sync for uncollected category, skipping.")
				continue
			}
			s, ok := syncerMap[key]
			if !ok {
				log.Warn().Str("key", key).Msg("Server returned unknown sync category, skipping.")
				continue
			}
			s.syncData(session, data, snap.hashes[key])
		}
	}

	// firewall is always synced separately (not hashed).
	if fullSync || slices.Contains(keys, "firewall") {
		syncFirewallData()
	}

	if fullSync {
		syncAccessPolicy(session)
	}

	log.Info().Msg("Completed system information synchronization.")
}

func syncServerData(session *scheduler.Session) {
	loadAvg, err := getLoadAverage()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to retrieve load average.")
	}
	entry := commitDefs["server"]
	data := &ServerData{
		Version:    version.Version,
		PamVersion: utils.GetPamVersion(),
		Load:       loadAvg,
	}
	scheduler.Rqueue.Patch(utils.JoinPath(entry.URL, entry.URLSuffix), data, 80, time.Time{})
}

func syncFirewallData() {
	if utils.IsFirewallDisabled() {
		log.Debug().Msg("Skipping firewall sync - firewall functionality is disabled")
		return
	}
	log.Debug().Msg("Firewall sync delegated to executor FirewallHandler")
}

func syncAccessPolicy(session *scheduler.Session) {
	resp, statusCode, err := session.Get(accessPolicyURL, 10)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch access policy")
		return
	}
	if statusCode == http.StatusNotFound {
		log.Debug().Msg("Access policy endpoint not available on this server")
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		log.Warn().Int("status_code", statusCode).Msg("Failed to fetch access policy")
		return
	}

	var accessPolicy AccessPolicy
	if err := json.Unmarshal(resp, &accessPolicy); err != nil {
		log.Warn().Err(err).Msg("Failed to parse access policy")
		return
	}

	if authManager != nil {
		authManager.UpdateBlockLocalSudo(accessPolicy.BlockLocalSudo)
	}
}

// syncRequiredKeys sends hashes to the server and returns the list of categories
// that need syncing. On server error, falls back to all collected categories
// in the original syncers registration order for predictable behavior.
func syncRequiredKeys(session *scheduler.Session, snap syncSnapshot) []string {
	required, err := checkSyncHashes(session, snap.hashes)
	if err != nil {
		log.Debug().Err(err).Msg("Sync-check failed, falling back to full sync.")
		required = make([]string, 0, len(snap.data))
		for _, s := range syncers {
			if _, ok := snap.data[s.Key()]; ok {
				required = append(required, s.Key())
			}
		}
		return required
	}

	// Normalize server-provided keys to the deterministic syncers registration order.
	requiredSet := make(map[string]struct{}, len(required))
	for _, key := range required {
		requiredSet[key] = struct{}{}
	}
	normalized := make([]string, 0, len(required))
	for _, s := range syncers {
		if _, ok := requiredSet[s.Key()]; ok {
			normalized = append(normalized, s.Key())
			delete(requiredSet, s.Key())
		}
	}
	for key := range requiredSet {
		log.Warn().Str("key", key).Msg("Server returned unknown sync category, ignoring.")
	}
	return normalized
}

// checkSyncHashes sends per-category data hashes to the server and returns the
// list of categories that need syncing. On error (old server returning 404,
// network failure, etc.), the caller should fall back to syncing all categories.
func checkSyncHashes(session *scheduler.Session, hashes SyncHashes) ([]string, error) {
	payload := map[string]any{"hashes": hashes}

	resp, statusCode, err := session.Post(syncCheckURL, payload, 10)
	if err != nil {
		return nil, fmt.Errorf("sync-check request failed: %w", err)
	}
	if statusCode != http.StatusOK {
		snippet := resp
		if len(snippet) > 256 {
			snippet = snippet[:256]
		}
		return nil, fmt.Errorf("sync-check returned HTTP %d: %s", statusCode, snippet)
	}

	var result struct {
		SyncRequired []string `json:"sync_required"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("sync-check response parse failed: %w", err)
	}

	return result.SyncRequired, nil
}

func compareData(entry commitDef, currentData, remoteData ComparableData, syncHash string) {
	var createData, updateData interface{}

	if remoteData == nil {
		createData = currentData.GetData()
	} else {
		// Compare using GetComparableData() to exclude fields not stored by server
		if !cmp.Equal(currentData.GetComparableData(), remoteData.GetComparableData()) {
			// Transmit using GetData() to include all raw data for server-side processing
			updateData = currentData.GetData()
		}
	}
	h := syncHashHeader(syncHash)
	if createData != nil {
		scheduler.Rqueue.PostWithHeaders(entry.URL, createData, 80, time.Time{}, h)
	} else if updateData != nil {
		scheduler.Rqueue.PatchWithHeaders(entry.URL+remoteData.GetID()+"/", updateData, 80, time.Time{}, h)
	}
}

func compareListData[T ComparableData](entry commitDef, currentData, remoteData []T, syncHash string) {
	h := syncHashHeader(syncHash)

	currentMap := make(map[interface{}]ComparableData)
	for _, currentItem := range currentData {
		currentMap[currentItem.GetKey()] = currentItem
	}

	for _, remoteItem := range remoteData {
		if currentItem, exists := currentMap[remoteItem.GetKey()]; exists {
			// Compare using GetComparableData() to exclude fields not stored by server
			if !cmp.Equal(currentItem.GetComparableData(), remoteItem.GetComparableData()) {
				// Transmit using GetData() to include all raw data for server-side processing
				scheduler.Rqueue.PatchWithHeaders(entry.URL+remoteItem.GetID()+"/", currentItem.GetData(), 80, time.Time{}, h)
			}
			delete(currentMap, currentItem.GetKey())
		} else {
			scheduler.Rqueue.DeleteWithHeaders(entry.URL+remoteItem.GetID()+"/", nil, 80, time.Time{}, h)
		}
	}

	var createData []interface{}
	for _, currentItem := range currentMap {
		createData = append(createData, currentItem.GetData())
	}
	if len(createData) > 0 {
		scheduler.Rqueue.PostWithHeaders(entry.URL, createData, 80, time.Time{}, h)
	}
}

func collectData() *commitData {
	data := &commitData{
		Version:    version.Version,
		PamVersion: utils.GetPamVersion(),
	}

	if load, err := getLoadAverage(); err == nil {
		data.Load = load
	} else {
		log.Debug().Err(err).Msg("Failed to retrieve load average.")
	}

	for _, s := range syncers {
		result, err := s.Collect()
		if err != nil {
			log.Debug().Err(err).Msgf("Failed to collect %s data.", s.Key())
			continue
		}
		assignToCommitData(data, s.Key(), result)
		if hash := s.ComputeHash(result); hash != "" {
			if data.SyncHashes == nil {
				data.SyncHashes = make(SyncHashes, len(syncers))
			}
			data.SyncHashes[s.Key()] = hash
		}
	}

	return data
}

func getLoadAverage() (float64, error) {
	avg, err := load.Avg()
	if err != nil {
		return 0, err
	}
	return avg.Load1, nil
}

func getSystemData() (SystemData, error) {
	cpuInfo, err := cpu.Info()
	if err != nil {
		return SystemData{}, err
	}

	hostInfo, err := host.Info()
	if err != nil {
		return SystemData{}, err
	}

	vm, err := mem.VirtualMemory()
	if err != nil {
		return SystemData{}, err
	}

	cpuPhysicalCores, err := cpu.Counts(false) // physical cores
	if err != nil {
		return SystemData{}, err
	}

	cpuLogicalCores, err := cpu.Counts(true) // logical cores
	if err != nil {
		return SystemData{}, err
	}

	return SystemData{
		UUID:             hostInfo.HostID,
		CPUType:          hostInfo.KernelArch,
		CPUBrand:         cpuInfo[0].ModelName,
		CPUPhysicalCores: cpuPhysicalCores,
		CPULogicalCores:  cpuLogicalCores,
		PhysicalMemory:   vm.Total,
		HardwareVendor:   cpuInfo[0].VendorID,
		HardwareModel:    cpuInfo[0].Model,
		HardwareSerial:   cpuInfo[0].PhysicalID,
		ComputerName:     hostInfo.Hostname,
		Hostname:         hostInfo.Hostname,
		LocalHostname:    hostInfo.Hostname,
	}, nil
}

func getOsData() (OSData, error) {
	major, minor, patch := 0, 0, 0

	hostInfo, err := host.Info()
	if err != nil {
		return OSData{}, err
	}

	versionParts := strings.Split(hostInfo.PlatformVersion, ".")
	if len(versionParts) > 0 {
		major, _ = strconv.Atoi(versionParts[0])
	}
	if len(versionParts) > 1 {
		minor, _ = strconv.Atoi(versionParts[1])
	}
	if len(versionParts) > 2 {
		patch, _ = strconv.Atoi(versionParts[2])
	}

	return OSData{
		Name:         hostInfo.Platform,
		Version:      hostInfo.PlatformVersion,
		Major:        major,
		Minor:        minor,
		Patch:        patch,
		Platform:     hostInfo.Platform,
		PlatformLike: utils.PlatformLike,
	}, nil
}

func getTimeData() (TimeData, error) {
	currentTime := time.Now()

	uptime, err := host.Uptime()
	if err != nil {
		return TimeData{}, err
	}

	timezone, _ := currentTime.Zone()

	return TimeData{
		Datetime: currentTime.Format(time.RFC3339),
		Timezone: timezone,
		Uptime:   uptime,
	}, nil
}

func getNetworkInterfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return []Interface{}, err
	}

	interfaces := []Interface{}
	for _, iface := range ifaces {
		mac := iface.HardwareAddr.String()
		if mac == "" {
			continue
		}

		if utils.VirtualIfacePattern.MatchString(iface.Name) {
			continue
		}

		interfaces = append(interfaces, Interface{
			Name:      iface.Name,
			Flags:     getFlags(iface),
			MTU:       iface.MTU,
			Mac:       mac,
			Type:      0, // TODO
			LinkSpeed: 0, // TODO
		})
	}

	return interfaces, nil
}

func getNetworkAddresses() ([]Address, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	addresses := []Address{}
	for _, iface := range ifaces {
		mac := iface.HardwareAddr.String()
		if mac == "" {
			continue
		}

		if utils.VirtualIfacePattern.MatchString(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			var mask net.IPMask
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				mask = v.Mask
			case *net.IPAddr:
				ip = v.IP
				mask = ip.DefaultMask()
			}
			if ip == nil || ip.To4() == nil {
				continue
			}
			addresses = append(addresses, Address{
				Address:       ip.To4().String(),
				Broadcast:     calculateBroadcastAddress(ip, mask),
				InterfaceName: iface.Name,
				Mask:          net.IP(mask).String(),
			})
		}
	}
	return addresses, nil
}

func getFlags(iface net.Interface) int {
	var flags int
	if iface.Flags&net.FlagUp != 0 {
		flags |= IFF_UP
	}
	if iface.Flags&net.FlagLoopback != 0 {
		flags |= IFF_LOOPBACK
	}
	if iface.Flags&net.FlagPointToPoint != 0 {
		flags |= IFF_POINTOPOINT
	}
	if iface.Flags&net.FlagRunning != 0 {
		flags |= IFF_RUNNING
	}
	return flags
}

func calculateBroadcastAddress(ip net.IP, mask net.IPMask) string {
	// only ipv4
	if ip.To4() == nil || len(mask) != net.IPv4len {
		return ""
	}

	broadcast := make(net.IP, len(ip.To4()))
	for i := 0; i < len(ip.To4()); i++ {
		broadcast[i] = ip[i] | ^mask[i]
	}

	return broadcast.String()
}

func getDisks() ([]Disk, error) {
	ioCounters, err := disk.IOCounters()
	seen := make(map[string]bool)

	if err != nil {
		return []Disk{}, err
	}

	disks := []Disk{}
	for name, ioCounter := range ioCounters {
		if utils.IsVirtualDisk(name) {
			continue
		}

		baseName := utils.GetDiskBaseName(name)
		if seen[baseName] {
			continue
		}
		seen[baseName] = true

		disks = append(disks, Disk{
			Name:         baseName,
			SerialNumber: ioCounter.SerialNumber,
			Label:        ioCounter.Label,
		})
	}

	slices.SortFunc(disks, func(a, b Disk) int {
		return strings.Compare(a.Name, b.Name)
	})
	return disks, nil
}

func getPartitions() ([]Partition, error) {
	seen := make(map[string]Partition)
	partitions, err := disk.Partitions(true)
	if err != nil {
		return []Partition{}, nil
	}

	for _, partition := range partitions {
		if utils.IsVirtualFileSystem(partition.Device, partition.Fstype, partition.Mountpoint) {
			continue
		}

		if value, exists := seen[partition.Device]; exists {
			value.MountPoints = append(value.MountPoints, partition.Mountpoint)
			seen[partition.Device] = value
			continue
		}
		disk := utils.ParseDiskName(partition.Device)
		seen[partition.Device] = Partition{
			Name:        partition.Device,
			MountPoints: []string{partition.Mountpoint},
			DiskName:    disk,
			Fstype:      partition.Fstype,
			IsVirtual:   utils.IsVirtualFileSystem(partition.Device, partition.Fstype, partition.Mountpoint),
		}
	}

	var partitionList []Partition
	for _, partition := range seen {
		slices.Sort(partition.MountPoints)
		partitionList = append(partitionList, partition)
	}
	slices.SortFunc(partitionList, func(a, b Partition) int {
		return strings.Compare(a.Name, b.Name)
	})
	return partitionList, nil
}
