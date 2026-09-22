package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ifaceFixture describes one interface in a fake sysfs tree.
type ifaceFixture struct {
	name string
	// hardware gives the entry the device symlink sysfs creates for an
	// interface driven by a device on a bus.
	hardware bool
	// devType is the DEVTYPE the entry's uevent carries, if any.
	devType string
	// markerDir is a settings directory of the interface's kind, such as
	// bridge or bonding, for the kernels that record no device type for it.
	markerDir string
	// linkDir files the entry under this directory and links to it from
	// /sys/class/net, the way sysfs links an interface to its place in the
	// device tree. An entry without one is a plain directory, which is what a
	// fixture uses when the link is not what is under test.
	linkDir string
}

// writeSysClassNet builds a fake /sys/class/net and returns its path.
func writeSysClassNet(t *testing.T, fixtures []ifaceFixture) string {
	t.Helper()

	root := t.TempDir()
	classNet := filepath.Join(root, "sys", "class", "net")
	require.NoError(t, os.MkdirAll(classNet, 0o755))

	for _, fixture := range fixtures {
		dir := filepath.Join(classNet, fixture.name)
		if fixture.linkDir != "" {
			target := filepath.Join(root, filepath.FromSlash(fixture.linkDir), fixture.name)
			require.NoError(t, os.MkdirAll(target, 0o755))
			require.NoError(t, os.Symlink(target, dir))
			dir = target
		} else {
			require.NoError(t, os.MkdirAll(dir, 0o755))
		}

		uevent := fmt.Sprintf("INTERFACE=%s\nIFINDEX=2\n", fixture.name)
		if fixture.devType != "" {
			uevent = fmt.Sprintf("INTERFACE=%s\nIFINDEX=2\nDEVTYPE=%s\n", fixture.name, fixture.devType)
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, "uevent"), []byte(uevent), 0o644))

		if fixture.hardware {
			device := filepath.Join(root, "sys", "devices", "pci0000:00", fixture.name)
			require.NoError(t, os.MkdirAll(device, 0o755))
			require.NoError(t, os.Symlink(device, filepath.Join(dir, "device")))
		}

		if fixture.markerDir != "" {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, fixture.markerDir), 0o755))
		}
	}

	return classNet
}

// useSysClassNet points the detector at a fixture tree for the duration of a
// test.
func useSysClassNet(t *testing.T, path string) {
	t.Helper()

	previous := sysClassNet
	t.Cleanup(func() { sysClassNet = previous })
	sysClassNet = path
}

func TestReportableInterfaceByLinkKind(t *testing.T) {
	fixtures := []ifaceFixture{
		{name: "eth0", hardware: true, linkDir: "sys/devices/pci0000:00/net"},
		{name: "enp0s31f6", hardware: true, linkDir: "sys/devices/pci0000:00/net"},
		{name: "wlan0", hardware: true},
		// A hardware name the kernel files under the virtual tree: this is
		// what the interface of a container looks like from inside it.
		{name: "eth1", linkDir: "sys/devices/virtual/net"},
		{name: "br0", devType: "bridge"},
		{name: "br1", markerDir: "bridge"},
		{name: "bond0", devType: "bond"},
		{name: "bond1", markerDir: "bonding"},
		{name: "eth0.100", devType: "vlan"},
		{name: "vxlan0", devType: "vxlan"},
		{name: "docker0", devType: "bridge"},
		{name: "veth9f2a1c", linkDir: "sys/devices/virtual/net"},
		{name: "cali1a2b3c4d5e6"},
		{name: "macvlan0", devType: "macvlan"},
		{name: "macvlan1"},
		{name: "ipvlan0", devType: "ipvlan"},
		{name: "dummy0"},
		{name: "tap0"},
	}

	tests := []struct {
		name     string
		iface    string
		include  []string
		reported bool
	}{
		{name: "a card on a bus is reported", iface: "eth0", reported: true},
		{name: "a card under a predictable name is reported", iface: "enp0s31f6", reported: true},
		{name: "a wireless card is reported", iface: "wlan0", reported: true},
		{name: "a hardware name the kernel calls virtual is left out", iface: "eth1"},
		{name: "a bridge is reported", iface: "br0", reported: true},
		{name: "a bridge without a device type is reported", iface: "br1", reported: true},
		{name: "a bond is reported", iface: "bond0", reported: true},
		{name: "a bond without a device type is reported", iface: "bond1", reported: true},
		{name: "a vlan is reported", iface: "eth0.100", reported: true},
		{name: "a vxlan is reported", iface: "vxlan0", reported: true},
		// The kind decides, not the name: a bridge a container runtime created
		// is a bridge like any other.
		{name: "a container runtime bridge is reported", iface: "docker0", reported: true},
		{name: "one half of a veth pair is left out", iface: "veth9f2a1c"},
		{name: "a container network device is left out", iface: "cali1a2b3c4d5e6"},
		// Reported only when asked for: a macvlan or ipvlan child is a device
		// of whatever holds it, not of the host. Whether the kernel records a
		// device type for the kind makes no difference to the answer, which is
		// why the kind is read from that type rather than from how the
		// interface is wired.
		{name: "a macvlan child is left out", iface: "macvlan0"},
		{name: "a macvlan child with no device type is left out", iface: "macvlan1"},
		{name: "an ipvlan child is left out", iface: "ipvlan0"},
		{name: "a dummy interface is left out", iface: "dummy0"},
		{name: "a tap device is left out", iface: "tap0"},
		{
			name:     "an include entry reports a veth half anyway",
			iface:    "veth9f2a1c",
			include:  []string{"veth9f2a1c"},
			reported: true,
		},
		{
			name:     "an include glob reports a container network device anyway",
			iface:    "cali1a2b3c4d5e6",
			include:  []string{"cali*"},
			reported: true,
		},
		{
			name:     "an include entry reports a macvlan child anyway",
			iface:    "macvlan0",
			include:  []string{"macvlan0"},
			reported: true,
		},
		// An interface sysfs has nothing to say about falls back to the name.
		{name: "an unknown interface with a virtual name is left out", iface: "veth0"},
		{name: "an unknown interface with no virtual name is reported", iface: "eth9", reported: true},
	}

	useSysClassNet(t, writeSysClassNet(t, fixtures))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.reported,
				reportableInterface(tt.iface, testMAC, false, tt.include),
				"reportableInterface(%q)", tt.iface)
		})
	}
}

func TestReportableInterfaceLeavesOutLoopbackWhateverItsKind(t *testing.T) {
	useSysClassNet(t, writeSysClassNet(t, []ifaceFixture{{name: "lo"}}))

	assert.False(t, reportableInterface("lo", testMAC, true, nil))
	assert.False(t, reportableInterface("lo", testMAC, true, []string{"lo"}),
		"the include list does not bring loopback back")
}

func TestInterfaceKindRefusesNamesThatAreNotOneElement(t *testing.T) {
	useSysClassNet(t, writeSysClassNet(t, []ifaceFixture{{name: "eth0", hardware: true}}))

	for _, name := range []string{"", ".", "..", "../eth0", "sub/eth0"} {
		assert.Equal(t, kindUnknown, interfaceKind(name),
			"a name that is not a single path element resolves to no kind: %q", name)
	}
}

func TestInterfaceKindWithoutSysfs(t *testing.T) {
	useSysClassNet(t, filepath.Join(t.TempDir(), "absent"))

	assert.Equal(t, kindUnknown, interfaceKind("eth0"),
		"with no sysfs to read, the kind is unknown and the name decides")
}
