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

func TestReportableInterfacesReadsTheConfiguredIncludeList(t *testing.T) {
	previous := config.GlobalSettings
	t.Cleanup(func() { config.GlobalSettings = previous })

	listed := []Iface{
		{Name: hardwareTestIface, Mac: testMAC},
		{Name: virtualTestIface, Mac: testMAC},
	}

	config.GlobalSettings.IncludeVirtualInterfaces = nil
	assert.Equal(t, map[string]bool{hardwareTestIface: true}, ReportableInterfaces(listed),
		"with an empty include list an interface of an excluded kind is left out")

	config.GlobalSettings.IncludeVirtualInterfaces = []string{virtualTestIface}
	assert.Equal(t, map[string]bool{hardwareTestIface: true, virtualTestIface: true},
		ReportableInterfaces(listed), "an interface the include list names is reported")
}

// The rule that keeps a report from being empty applies to whatever the machine
// has, not only to the kinds one platform can name.
func TestReportableInterfacesNeverReportsNothing(t *testing.T) {
	reported := reportableInterfaces([]Iface{
		{Name: virtualTestIface, Mac: testMAC},
		{Name: "loopbackreportcheck0", Mac: testMAC, Loopback: true},
		{Name: "addresslessreportcheck0"},
	}, nil)

	assert.Equal(t, map[string]bool{virtualTestIface: true}, reported,
		"with nothing else to report, an interface of an excluded kind is reported, "+
			"and loopback and an interface with no hardware address still are not")
}

func TestReportableInterfacesReportsNothingWhenThereIsNothingToReport(t *testing.T) {
	reported := reportableInterfaces([]Iface{
		{Name: "loopbackreportcheck0", Mac: testMAC, Loopback: true},
		{Name: "addresslessreportcheck0"},
	}, nil)

	assert.Empty(t, reported,
		"loopback and an interface with no hardware address are not reported to fill an empty report")
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
