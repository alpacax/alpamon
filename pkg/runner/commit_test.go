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
		assert.NotEmpty(t, user.Shell, "Shell should not be empty.")
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
