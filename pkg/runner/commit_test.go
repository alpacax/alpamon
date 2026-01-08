package runner

import (
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
