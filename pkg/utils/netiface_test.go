package utils

import (
	"testing"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/stretchr/testify/assert"

	"github.com/alpacax/alpamon/v2/pkg/config"
)

// The names below are deliberately ones no machine carries. A test that names
// a real interface would ask the platform detector about it, and the answer
// would depend on the machine the test runs on.
const (
	virtualTestIface  = "vethreportcheck0"
	hardwareTestIface = "nicreportcheck0"
	testMAC           = "02:00:00:00:00:01"
)

func TestReportableInterface(t *testing.T) {
	tests := []struct {
		name     string
		iface    string
		mac      string
		loopback bool
		include  []string
		reported bool
	}{
		{
			name:     "an interface with no known virtual name is reported",
			iface:    hardwareTestIface,
			mac:      testMAC,
			reported: true,
		},
		{
			name:  "a virtual interface is left out",
			iface: virtualTestIface,
			mac:   testMAC,
		},
		{
			name:     "an include entry naming it reports it anyway",
			iface:    virtualTestIface,
			mac:      testMAC,
			include:  []string{virtualTestIface},
			reported: true,
		},
		{
			name:     "an include glob matching it reports it anyway",
			iface:    virtualTestIface,
			mac:      testMAC,
			include:  []string{"vethreport*"},
			reported: true,
		},
		{
			name:    "an include entry naming another interface changes nothing",
			iface:   virtualTestIface,
			mac:     testMAC,
			include: []string{"vethsomethingelse0"},
		},
		{
			name:     "loopback is left out",
			iface:    hardwareTestIface,
			mac:      testMAC,
			loopback: true,
		},
		{
			name:     "the include list does not bring loopback back",
			iface:    hardwareTestIface,
			mac:      testMAC,
			loopback: true,
			include:  []string{hardwareTestIface},
		},
		{
			name:  "an interface with no hardware address is left out",
			iface: hardwareTestIface,
		},
		{
			name:    "the include list does not bring back an interface with no hardware address",
			iface:   hardwareTestIface,
			include: []string{hardwareTestIface},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.reported,
				reportableInterface(tt.iface, tt.mac, tt.loopback, tt.include))
		})
	}
}

func TestInventoryInterfacesReportsWhatTheNamePatternReports(t *testing.T) {
	tests := []struct {
		name     string
		iface    string
		reported bool
	}{
		// The inventory filter is the one the agent has always applied. These
		// cases are what it reported before the link kind was read at all, and
		// none of them may change.
		{"ethernet", "eth0", true},
		{"predictable onboard", "enp0s31f6", true},
		{"predictable slot", "enp0s3", true},
		{"onboard", "eno1", true},
		{"ens", "ens192", true},
		{"wlan", "wlan0", true},
		{"darwin ethernet", "en0", true},
		{"host bridge", "br0", true},
		{"bond", "bond0", true},
		{"vlan", "eth0.100", true},
		{"loopback", "lo", false},
		{"docker", "docker0", false},
		{"veth", "veth1234abc", false},
		{"container bridge", "br-abc123", false},
		{"virbr", "virbr0", false},
		{"vmnet", "vmnet8", false},
		{"tap", "tap0", false},
		{"tun", "tun0", false},
		{"wireguard", "wg0", false},
		{"zerotier", "zt0", false},
		{"tailscale", "tailscale0", false},
		{"cni", "cni0", false},
		{"utun", "utun0", false},
		{"awdl", "awdl0", false},
		{"llw", "llw0", false},
		{"darwin bridge", "bridge0", false},
		{"anpi", "anpi0", false},
		{"ap", "ap1", false},
		{"windows loopback", "Loopback Pseudo-Interface 1", false},
		{"isatap", "isatap.localdomain", false},
		{"teredo", "Teredo Tunneling Pseudo-Interface", false},
		{"6to4", "6to4 Adapter", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reported := byNameInterfaces([]Iface{{Name: tt.iface, Mac: testMAC}}, nil)
			assert.Equal(t, tt.reported, reported[tt.iface], "the inventory reports %q", tt.iface)
		})
	}
}

func TestInventoryInterfacesAndTheIncludeList(t *testing.T) {
	listed := []Iface{
		{Name: "docker0", Mac: testMAC},
		{Name: "lo", Mac: testMAC, Loopback: true},
		{Name: "addresslessreportcheck0"},
	}

	assert.Empty(t, byNameInterfaces(listed, nil),
		"the name pattern leaves out all three")

	assert.Equal(t, map[string]bool{"docker0": true}, byNameInterfaces(listed, []string{"docker0"}),
		"the include list reports an interface the pattern leaves out")

	assert.Empty(t, byNameInterfaces(listed, []string{"lo", "addresslessreportcheck0"}),
		"the include list reports neither loopback nor an interface with no hardware address")
}

// With the setting off, which is how it ships, the inventory is what the name
// pattern reports and the link kind changes nothing about it.
func TestInventoryInterfacesFollowTheSetting(t *testing.T) {
	listed := []Iface{
		{Name: hardwareTestIface, Mac: testMAC},
		{Name: virtualTestIface, Mac: testMAC},
	}

	assert.Equal(t, byNameInterfaces(listed, nil), inventoryInterfaces(listed, nil, false),
		"with the setting off the inventory is what the name pattern reports")
	assert.Equal(t, byKindInterfaces(listed, nil), inventoryInterfaces(listed, nil, true),
		"with the setting on the inventory is what the link kind reports")
}

func TestInterfacesReadTheConfiguredSettings(t *testing.T) {
	previous := config.GlobalSettings
	t.Cleanup(func() { config.GlobalSettings = previous })

	listed := []Iface{
		{Name: hardwareTestIface, Mac: testMAC},
		{Name: virtualTestIface, Mac: testMAC},
	}

	config.GlobalSettings.IncludeVirtualInterfaces = nil
	config.GlobalSettings.ExcludeVirtualFromInventory = false
	assert.Equal(t, map[string]bool{hardwareTestIface: true}, InventoryInterfaces(listed))
	assert.Equal(t, map[string]bool{hardwareTestIface: true}, TrafficInterfaces(listed))

	config.GlobalSettings.IncludeVirtualInterfaces = []string{virtualTestIface}
	assert.Equal(t, map[string]bool{hardwareTestIface: true, virtualTestIface: true},
		InventoryInterfaces(listed), "an interface the include list names is in the inventory")
	assert.Equal(t, map[string]bool{hardwareTestIface: true, virtualTestIface: true},
		TrafficInterfaces(listed), "and it carries traffic too")
}

// Traffic is reported for what the inventory holds and nothing else, so an
// interface the inventory leaves out cannot come back through the kind rules.
func TestTrafficInterfacesStayWithinTheInventory(t *testing.T) {
	listed := []Iface{
		{Name: hardwareTestIface, Mac: testMAC},
		{Name: "docker0", Mac: testMAC},
		{Name: "lo", Mac: testMAC, Loopback: true},
	}

	inventory := inventoryInterfaces(listed, nil, false)
	traffic := trafficInterfaces(listed, nil, false)

	assert.Equal(t, map[string]bool{hardwareTestIface: true}, inventory)
	for name := range traffic {
		assert.True(t, inventory[name], "traffic is reported for %q, which the inventory does not hold", name)
	}
}

// The kind rules never leave a machine reporting traffic for nothing at all.
func TestByKindInterfacesNeverReportsNothing(t *testing.T) {
	reported := byKindInterfaces([]Iface{
		{Name: virtualTestIface, Mac: testMAC},
		{Name: "loopbackreportcheck0", Mac: testMAC, Loopback: true},
		{Name: "addresslessreportcheck0"},
	}, nil)

	assert.Equal(t, map[string]bool{virtualTestIface: true}, reported,
		"with nothing else to report, an interface of an excluded kind is reported, "+
			"and loopback and an interface with no hardware address still are not")
}

func TestByKindInterfacesReportsNothingWhenThereIsNothingToReport(t *testing.T) {
	reported := byKindInterfaces([]Iface{
		{Name: "loopbackreportcheck0", Mac: testMAC, Loopback: true},
		{Name: "addresslessreportcheck0"},
	}, nil)

	assert.Empty(t, reported,
		"loopback and an interface with no hardware address are not reported to fill an empty set")
}

func TestMatchesInterfacePattern(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		iface    string
		matched  bool
	}{
		{"an exact name matches", []string{"br0"}, "br0", true},
		{"an exact name matches nothing else", []string{"br0"}, "br1", false},
		{"a glob matches its prefix", []string{"veth*"}, "veth1a2b3c", true},
		{"a glob matches nothing outside it", []string{"veth*"}, "docker0", false},
		{"a single-character glob matches", []string{"br?"}, "br0", true},
		{"one of several patterns is enough", []string{"br0", "veth*"}, "veth0", true},
		{"an empty list matches nothing", nil, "br0", false},
		{"a malformed pattern matches no other name", []string{"[veth"}, "veth0", false},
		{"a name is matched as itself when a glob cannot parse it", []string{"[veth"}, "[veth", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.matched, matchesInterfacePattern(tt.patterns, tt.iface))
		})
	}
}

func TestHasVirtualIfacePrefix(t *testing.T) {
	tests := []struct {
		name    string
		iface   string
		virtual bool
	}{
		{"docker", "docker0", true},
		{"veth", "veth1234abc", true},
		{"container bridge", "br-abc123", true},
		{"virbr", "virbr0", true},
		{"vmnet", "vmnet8", true},
		{"tap", "tap0", true},
		{"tun", "tun0", true},
		{"wireguard", "wg0", true},
		{"zerotier", "zt0", true},
		{"tailscale", "tailscale0", true},
		{"cni", "cni0", true},
		// Hardware interface names, including the predictable names of the
		// onboard and hypervisor-default cards on PCI bus 0.
		{"ethernet", "eth0", false},
		{"wlan", "wlan0", false},
		{"ens", "ens192", false},
		{"enp onboard", "enp0s31f6", false},
		{"enp slot 3", "enp0s3", false},
		{"eno onboard", "eno1", false},
		// Names of configured virtual links. The kind decides whether these are
		// reported, so the prefixes do not claim them.
		{"host bridge", "br0", false},
		{"bond", "bond0", false},
		{"vlan", "eth0.100", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.virtual, hasVirtualIfacePrefix(tt.iface),
				"hasVirtualIfacePrefix(%q)", tt.iface)
		})
	}
}

// FilterVirtualInterface is the traffic side, so it reports what the inventory
// holds less the kinds that are left out.
func TestFilterVirtualInterface(t *testing.T) {
	ifaces := net.InterfaceStatList{
		{Name: hardwareTestIface, HardwareAddr: testMAC, Flags: []string{"up", "broadcast", "multicast"}},
		{Name: virtualTestIface, HardwareAddr: testMAC, Flags: []string{"up"}},
		{Name: "loopbackreportcheck0", HardwareAddr: testMAC, Flags: []string{"up", "loopback"}},
		{Name: "addresslessreportcheck0", HardwareAddr: "", Flags: []string{"up"}},
	}

	filtered := FilterVirtualInterface(ifaces)

	assert.Contains(t, filtered, hardwareTestIface)
	assert.NotContains(t, filtered, virtualTestIface)
	assert.NotContains(t, filtered, "loopbackreportcheck0",
		"the loopback flag is spelled the way the interface source spells it")
	assert.NotContains(t, filtered, "addresslessreportcheck0")
}

func TestHasLoopbackFlag(t *testing.T) {
	assert.True(t, hasLoopbackFlag([]string{"up", "loopback"}))
	assert.True(t, hasLoopbackFlag([]string{"Loopback"}), "the flag is matched whatever its case")
	assert.False(t, hasLoopbackFlag([]string{"up", "broadcast", "multicast"}))
	assert.False(t, hasLoopbackFlag(nil))
}
