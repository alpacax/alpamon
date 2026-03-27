package runner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLoadAverage(t *testing.T) {
	avgData, err := getLoadAverage()
	assert.NoError(t, err, "Failed to get load average")

	assert.True(t, avgData >= 0, "Load average should be non-negative.")
}

func TestGetSystemData(t *testing.T) {
	systemData, err := getSystemData()
	assert.NoError(t, err, "Failed to get system data")

	assert.NotEmpty(t, systemData.UUID, "UUID should not be empty.")
	assert.NotEmpty(t, systemData.CPUBrand, "CPUBrand should not be empty.")
	assert.True(t, systemData.CPUPhysicalCores > 0, "Physical CPU cores should be greater than 0.")
	assert.True(t, systemData.CPULogicalCores > 0, "Logical CPU cores should be greater than 0.")
	assert.True(t, systemData.PhysicalMemory > 0, "Physical memory should be greater than 0.")
}

func TestGetOsData(t *testing.T) {
	osData, err := getOsData()
	assert.NoError(t, err, "Failed to get os data")

	assert.NotEmpty(t, osData.Name, "Name should not be empty.")
	assert.NotEmpty(t, osData.Version, "Version should not be empty.")
	assert.True(t, osData.Major >= 0, "Major version should be non-negative.")
	assert.True(t, osData.Minor >= 0, "Minor version should be non-negative.")
	assert.True(t, osData.Patch >= 0, "Patch version should be non-negative.")
	assert.NotEmpty(t, osData.Platform, "Platform should not be empty.")
}

func TestGetTimeData(t *testing.T) {
	timeData, err := getTimeData()
	assert.NoError(t, err, "Failed to get time data")

	assert.NotEmpty(t, timeData.Datetime, "Datetime should not be empty.")
	assert.NotEmpty(t, timeData.Timezone, "Timezone should not be empty.")
	assert.NotNil(t, timeData.Uptime, "Uptime should not be nil.")
}

func TestGetUserData(t *testing.T) {
	userData, err := getUserData()
	assert.NoError(t, err, "Failed to get user data")

	assert.NotEmpty(t, userData, "User data should not be empty.")
	for _, user := range userData {
		assert.NotEmpty(t, user.Username, "Username should not be empty.")
		assert.NotNil(t, user.UID, "uid should not be empty.")
		assert.NotNil(t, user.GID, "GID should not be empty.")
		assert.NotEmpty(t, user.Directory, "Directory should not be empty.")
		// Raw data fields may be nil if the corresponding system file is not readable
		// Server will determine login_enabled from these raw data fields
	}
}

func TestLoadValidShells(t *testing.T) {
	// This test verifies that loadValidShells can read and parse the shells file
	// On macOS/Linux, /etc/shells should exist with common shells
	shells := loadValidShells()

	// shells may be nil if /etc/shells is not readable, which is acceptable
	if shells != nil {
		// If shells file was read, it should contain at least one shell
		assert.True(t, len(shells) > 0, "Valid shells slice should not be empty when /etc/shells is readable")

		// Common shells that should be in the file on most systems
		commonShells := []string{"/bin/sh", "/bin/bash", "/bin/zsh"}
		foundAny := false
		for _, commonShell := range commonShells {
			for _, shell := range shells {
				if shell == commonShell {
					foundAny = true
					break
				}
			}
			if foundAny {
				break
			}
		}
		assert.True(t, foundAny, "At least one common shell should be in /etc/shells")
	}
}

func TestLoadShadowData(t *testing.T) {
	// This test verifies that loadShadowData can attempt to read the shadow file
	// Note: /etc/shadow requires root privileges on most systems
	shadowData := loadShadowData()

	// shadowData may be nil if /etc/shadow is not readable (permission denied)
	// This is expected behavior on non-root execution
	// The function should not panic or error
	// Note: range over nil map is safe and does nothing
	for username, entry := range shadowData {
		assert.NotEmpty(t, username, "Username should not be empty")
		assert.Equal(t, username, entry.username, "Entry username should match key")
		// expireDate is *int64 (may be nil)
	}
}

func TestGetUserDataWithRawFields(t *testing.T) {
	userData, err := getUserData()
	assert.NoError(t, err, "Failed to get user data")

	assert.NotEmpty(t, userData, "User data should not be empty.")
	for _, user := range userData {
		assert.NotEmpty(t, user.Username, "Username should not be empty.")
		// ValidShells will be set if /etc/shells was readable (same for all users)
		// ShadowExpireDate will be set if /etc/shadow was readable
		// These raw data fields enable server-side login_enabled determination
	}
}

func TestGetGroupData(t *testing.T) {
	groupData, err := getGroupData()
	assert.NoError(t, err, "Failed to get group data")

	assert.NotEmpty(t, groupData, "Group data should not be empty.")
	for _, group := range groupData {
		assert.NotEmpty(t, group.GroupName, "GroupName should not be empty.")
		assert.NotNil(t, group.GID, "GID should not be empty.")
	}
}

func TestGetNetworkInterfaces(t *testing.T) {
	networkInterfaces, err := getNetworkInterfaces()
	assert.NoError(t, err, "Failed to get network interfaces")

	assert.NotEmpty(t, networkInterfaces, "Network interfaces should not be empty.")
	for _, iface := range networkInterfaces {
		assert.NotEmpty(t, iface.Name, "Interface name should not be empty.")
		assert.NotEmpty(t, iface.Mac, "MAC address should not be empty.")
		assert.True(t, iface.MTU > 0, "MTU should be greater than 0.")
	}
}

func TestGetNetworkAddresses(t *testing.T) {
	addresses, err := getNetworkAddresses()
	assert.NoError(t, err, "Failed to get network addresses")

	assert.NotEmpty(t, addresses, "Network addresses should not be empty.")
	for _, addr := range addresses {
		assert.NotEmpty(t, addr.Address, "Address should not be empty.")
		assert.NotEmpty(t, addr.Broadcast, "Broadcast address should not be empty.")
		assert.NotEmpty(t, addr.InterfaceName, "Interface name should not be empty.")
		assert.NotEmpty(t, addr.Mask, "Mask should not be empty.")
	}
}

func TestUserDataGetComparableData(t *testing.T) {
	expireDate := int64(20000)
	user := UserData{
		ID:               "test-id",
		Username:         "testuser",
		UID:              1001,
		GID:              1001,
		Directory:        "/home/testuser",
		Shell:            "/bin/bash",
		ShadowExpireDate: &expireDate,
		ValidShells:      []string{"/bin/bash", "/bin/sh"},
	}

	// GetData should include all fields (for transmission)
	data := user.GetData().(UserData)
	assert.Equal(t, "testuser", data.Username)
	assert.Equal(t, 1001, data.UID)
	assert.Equal(t, "/bin/bash", data.Shell)
	assert.NotNil(t, data.ShadowExpireDate, "GetData should include ShadowExpireDate")
	assert.NotNil(t, data.ValidShells, "GetData should include ValidShells")
	assert.Equal(t, 2, len(data.ValidShells))

	// GetComparableData should exclude ValidShells (for comparison)
	comparable := user.GetComparableData().(UserData)
	assert.Equal(t, "testuser", comparable.Username)
	assert.Equal(t, 1001, comparable.UID)
	assert.Equal(t, "/bin/bash", comparable.Shell)
	assert.NotNil(t, comparable.ShadowExpireDate, "GetComparableData should include ShadowExpireDate (server stores it)")
	assert.Nil(t, comparable.ValidShells, "GetComparableData should exclude ValidShells (server doesn't store it)")
}

func TestCompareUserDataNoUnnecessaryPatch(t *testing.T) {
	expireDate := int64(20000)

	// Remote data from server (has shadow_expire_date, no valid_shells)
	remoteData := UserData{
		ID:               "1",
		Username:         "testuser",
		UID:              1001,
		GID:              1001,
		Directory:        "/home/testuser",
		Shell:            "/bin/bash",
		ShadowExpireDate: &expireDate,
		// ValidShells is nil - server doesn't store this field
	}

	// Current data from system (has all raw data)
	currentData := UserData{
		Username:         "testuser",
		UID:              1001,
		GID:              1001,
		Directory:        "/home/testuser",
		Shell:            "/bin/bash",
		ShadowExpireDate: &expireDate,
		ValidShells:      []string{"/bin/bash", "/bin/sh"},
	}

	// GetComparableData() should make them equal (excluding ValidShells)
	currentComparable := currentData.GetComparableData().(UserData)
	remoteComparable := remoteData.GetComparableData().(UserData)

	// Both should have ShadowExpireDate
	assert.NotNil(t, currentComparable.ShadowExpireDate)
	assert.NotNil(t, remoteComparable.ShadowExpireDate)

	// Both should have nil ValidShells
	assert.Nil(t, currentComparable.ValidShells)
	assert.Nil(t, remoteComparable.ValidShells)

	// They should be equal when compared
	assert.Equal(t, currentComparable, remoteComparable, "Comparable data should be equal")
}

func TestCompareUserDataDetectRealChanges(t *testing.T) {
	expireDate := int64(20000)
	newExpireDate := int64(30000)

	// Remote data from server
	remoteData := UserData{
		ID:               "1",
		Username:         "testuser",
		UID:              1001,
		GID:              1001,
		Directory:        "/home/testuser",
		Shell:            "/bin/bash",
		ShadowExpireDate: &expireDate,
	}

	// Current data with changed shell
	currentDataShellChanged := UserData{
		Username:         "testuser",
		UID:              1001,
		GID:              1001,
		Directory:        "/home/testuser",
		Shell:            "/bin/zsh", // Changed
		ShadowExpireDate: &expireDate,
		ValidShells:      []string{"/bin/bash", "/bin/zsh"},
	}

	// Current data with changed expire date
	currentDataExpireChanged := UserData{
		Username:         "testuser",
		UID:              1001,
		GID:              1001,
		Directory:        "/home/testuser",
		Shell:            "/bin/bash",
		ShadowExpireDate: &newExpireDate, // Changed
		ValidShells:      []string{"/bin/bash"},
	}

	// Shell change should be detected
	assert.NotEqual(t,
		currentDataShellChanged.GetComparableData(),
		remoteData.GetComparableData(),
		"Shell change should be detected")

	// Expire date change should be detected
	assert.NotEqual(t,
		currentDataExpireChanged.GetComparableData(),
		remoteData.GetComparableData(),
		"ShadowExpireDate change should be detected")
}

func TestTimeDataGetComparableData(t *testing.T) {
	timeData := TimeData{
		ID:       "test-id",
		Datetime: "2024-01-01T00:00:00Z",
		BootTime: 1704067200,
		Timezone: "Asia/Seoul",
		Uptime:   86400,
	}

	// GetData should include Datetime, Timezone, and Uptime (for transmission)
	data := timeData.GetData().(TimeData)
	assert.Equal(t, "2024-01-01T00:00:00Z", data.Datetime)
	assert.Equal(t, "Asia/Seoul", data.Timezone)
	assert.Equal(t, uint64(86400), data.Uptime)

	// GetComparableData should only include Timezone (for comparison)
	comparable := timeData.GetComparableData().(TimeData)
	assert.Equal(t, "Asia/Seoul", comparable.Timezone)
	assert.Empty(t, comparable.Datetime, "GetComparableData should exclude Datetime")
	assert.Equal(t, uint64(0), comparable.Uptime, "GetComparableData should exclude Uptime")
}

func TestTimeDataComparisonIgnoresDatetime(t *testing.T) {
	// Two TimeData with same timezone but different datetime/uptime
	time1 := TimeData{
		Datetime: "2024-01-01T00:00:00Z",
		Timezone: "Asia/Seoul",
		Uptime:   86400,
	}
	time2 := TimeData{
		Datetime: "2024-01-01T01:00:00Z",
		Timezone: "Asia/Seoul",
		Uptime:   90000,
	}

	// Comparable data should be equal (only Timezone matters)
	assert.Equal(t, time1.GetComparableData(), time2.GetComparableData(),
		"Same timezone with different datetime/uptime should be equal for comparison")

	// Different timezone should be detected
	time3 := TimeData{
		Datetime: "2024-01-01T00:00:00Z",
		Timezone: "US/Pacific",
		Uptime:   86400,
	}
	assert.NotEqual(t, time1.GetComparableData(), time3.GetComparableData(),
		"Different timezone should be detected")
}

func TestOtherTypesGetComparableData(t *testing.T) {
	// For other types, GetComparableData should return same as GetData

	// SystemData
	sysData := SystemData{UUID: "test-uuid", Hostname: "testhost"}
	assert.Equal(t, sysData.GetData(), sysData.GetComparableData())

	// OSData
	osData := OSData{Name: "linux", Version: "5.0"}
	assert.Equal(t, osData.GetData(), osData.GetComparableData())

	// GroupData
	groupData := GroupData{GID: 1000, GroupName: "testgroup"}
	assert.Equal(t, groupData.GetData(), groupData.GetComparableData())

	// Interface
	ifaceData := Interface{Name: "eth0", Mac: "00:00:00:00:00:00"}
	assert.Equal(t, ifaceData.GetData(), ifaceData.GetComparableData())
}

func TestSyncers(t *testing.T) {
	expectedKeys := []string{
		"info", "os", "time", "users", "groups",
		"interfaces", "addresses", "disks", "partitions",
	}

	assert.Len(t, syncers, len(expectedKeys), "Should have 9 syncers")

	// Verify all keys are present and unique
	seen := make(map[string]bool)
	for _, s := range syncers {
		key := s.Key()
		assert.False(t, seen[key], "Duplicate syncer key: %s", key)
		seen[key] = true
		assert.Contains(t, expectedKeys, key, "Unexpected syncer key: %s", key)

		// Verify Def() returns a valid commitDef
		def := s.Def()
		assert.NotEmpty(t, def.URL, "Syncer %s should have a URL", key)
		assert.NotEmpty(t, def.URLSuffix, "Syncer %s should have a URLSuffix", key)
	}

	for _, expected := range expectedKeys {
		assert.True(t, seen[expected], "Missing syncer for key: %s", expected)
	}
}

func TestSyncerCollect(t *testing.T) {
	for _, s := range syncers {
		// Collect may fail in certain environments (e.g., limited procfs or permissions in CI).
		// This test verifies that all syncers are wired correctly and Collect can be invoked.
		result, err := s.Collect()
		if err != nil {
			t.Logf("Collect returned error for %s: %v (allowed in this test)", s.Key(), err)
		}
		_ = result
	}
}

func TestComputeFingerprint(t *testing.T) {
	data := map[string]string{"key": "value"}
	hash := computeFingerprint(data)

	assert.True(t, strings.HasPrefix(hash, "sha256:"), "Hash should have sha256: prefix")
	assert.Len(t, hash, 7+64, "sha256: prefix (7) + 64 hex chars")

	// Determinism: same input produces same hash
	hash2 := computeFingerprint(data)
	assert.Equal(t, hash, hash2, "Same input should produce same hash")

	// Different input produces different hash
	hash3 := computeFingerprint(map[string]string{"key": "other"})
	assert.NotEqual(t, hash, hash3, "Different input should produce different hash")
}

func TestComputeFingerprintEmptyOnError(t *testing.T) {
	// Channels cannot be marshaled to JSON
	hash := computeFingerprint(make(chan int))
	assert.Equal(t, "", hash, "Should return empty string on marshal error")
}

func TestSyncerComputeHash(t *testing.T) {
	for _, s := range syncers {
		result, err := s.Collect()
		if err != nil {
			t.Logf("Collect returned error for %s: %v (skipping hash test)", s.Key(), err)
			continue
		}
		hash := s.ComputeHash(result)
		assert.True(t, strings.HasPrefix(hash, "sha256:"),
			"Syncer %s should produce sha256-prefixed hash, got: %s", s.Key(), hash)
		assert.Len(t, hash, 7+64,
			"Syncer %s hash should be 71 chars (sha256: + 64 hex)", s.Key())
	}
}

func TestTimeSyncerComputeHash(t *testing.T) {
	timeSyncer := syncerMap["time"]
	assert.NotNil(t, timeSyncer, "time syncer should exist")

	// Same timezone, different datetime/uptime should produce same hash
	time1 := TimeData{Datetime: "2024-01-01T00:00:00Z", Timezone: "Asia/Seoul", Uptime: 86400}
	time2 := TimeData{Datetime: "2024-01-01T01:00:00Z", Timezone: "Asia/Seoul", Uptime: 90000}
	assert.Equal(t, timeSyncer.ComputeHash(time1), timeSyncer.ComputeHash(time2),
		"Same timezone with different datetime/uptime should produce same hash")

	// Different timezone should produce different hash
	time3 := TimeData{Datetime: "2024-01-01T00:00:00Z", Timezone: "US/Pacific", Uptime: 86400}
	assert.NotEqual(t, timeSyncer.ComputeHash(time1), timeSyncer.ComputeHash(time3),
		"Different timezone should produce different hash")
}

func TestCollectDataIncludesSyncHashes(t *testing.T) {
	data := collectData()

	// SyncHashes should contain one entry per syncer category
	assert.Equal(t, len(syncers), len(data.SyncHashes),
		"SyncHashes should contain one entry per syncer")

	for _, s := range syncers {
		key := s.Key()
		hash, ok := data.SyncHashes[key]
		assert.True(t, ok, "SyncHashes should contain entry for %s", key)
		assert.NotEmpty(t, hash, "Hash for %s should not be empty", key)
		assert.True(t, strings.HasPrefix(hash, "sha256:"),
			"Hash for %s should have sha256: prefix, got %s", key, hash)
		assert.Len(t, hash, 7+64,
			"Hash for %s should be 71 chars (sha256: + 64 hex), got %d", key, len(hash))
	}

	// Verify sync_hashes is present in marshaled JSON
	jsonBytes, err := json.Marshal(data)
	assert.NoError(t, err)
	assert.Contains(t, string(jsonBytes), `"sync_hashes"`,
		"Marshaled commit payload should contain sync_hashes field")
}

func TestComputeFingerprintStructDeterminism(t *testing.T) {
	// Verify struct field ordering is deterministic across calls
	data := SystemData{
		UUID:             "test-uuid",
		CPUType:          "x86_64",
		CPUBrand:         "Intel",
		CPUPhysicalCores: 4,
		CPULogicalCores:  8,
		PhysicalMemory:   16000000000,
		Hostname:         "testhost",
	}

	hashes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		hashes[computeFingerprint(data)] = true
	}
	assert.Len(t, hashes, 1, "Same struct should always produce the same hash")
}

