package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ifaceFixture describes one interface in a fake sysfs tree. The tree is built
// with the shape a real one has: every interface under /sys/class/net is a
// symlink into the device tree, either under the bus device that drives it or
// under the kernel's virtual tree.
type ifaceFixture struct {
	name string
	// hardware files the entry under a bus device and gives it the device
	// symlink sysfs creates for an interface driven by one.
	hardware bool
	// devType is the DEVTYPE the entry's uevent carries, if any.
	devType string
	// tunFlags gives the entry the tun_flags attribute a tun or tap device
	// carries.
	tunFlags bool
	// stacked makes iflink point at another interface, as it does for one half
	// of a veth pair or for a child created on top of another interface. An
	// entry without it points at itself.
	stacked bool
	// plainDir leaves the entry a directory rather than a symlink, standing in
	// for a sysfs that is not shaped the way this detector expects.
	plainDir bool
}

// writeSysClassNet builds a fake /sys/class/net and returns its path.
func writeSysClassNet(t *testing.T, fixtures []ifaceFixture) string {
	t.Helper()

	root := t.TempDir()
	classNet := filepath.Join(root, "sys", "class", "net")
	require.NoError(t, os.MkdirAll(classNet, 0o755))

	for i, fixture := range fixtures {
		// Index 1 is loopback's on a real system, so the fixtures start above
		// it. A stacked interface points at the index below its own.
		index := i + 2
		link := index
		if fixture.stacked {
			link = index - 1
		}

		var dir string
		switch {
		case fixture.plainDir:
			dir = filepath.Join(classNet, fixture.name)
		case fixture.hardware:
			dir = filepath.Join(root, "sys", "devices", "pci0000:00", "0000:00:1f.6", "net", fixture.name)
		default:
			dir = filepath.Join(root, "sys", "devices", "virtual", "net", fixture.name)
		}
		require.NoError(t, os.MkdirAll(dir, 0o755))

		if !fixture.plainDir {
			require.NoError(t, os.Symlink(dir, filepath.Join(classNet, fixture.name)))
		}

		uevent := fmt.Sprintf("INTERFACE=%s\nIFINDEX=%d\n", fixture.name, index)
		if fixture.devType != "" {
			uevent = fmt.Sprintf("INTERFACE=%s\nIFINDEX=%d\nDEVTYPE=%s\n", fixture.name, index, fixture.devType)
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, "uevent"), []byte(uevent), 0o644))

		for attribute, value := range map[string]int{"ifindex": index, "iflink": link} {
			require.NoError(t, os.WriteFile(filepath.Join(dir, attribute),
				[]byte(strconv.Itoa(value)+"\n"), 0o644))
		}

		if fixture.hardware {
			device := filepath.Join(root, "sys", "devices", "pci0000:00", "0000:00:1f.6")
			require.NoError(t, os.Symlink(device, filepath.Join(dir, "device")))
		}

		if fixture.tunFlags {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "tun_flags"), []byte("0x1002\n"), 0o644))
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
		{name: "eth0", hardware: true},
		{name: "enp0s31f6", hardware: true},
		{name: "wlan0", hardware: true},
		{name: "br0", devType: "bridge"},
		{name: "br1"},
		{name: "bond0", devType: "bond"},
		{name: "eth0.100", devType: "vlan", stacked: true},
		{name: "vxlan0", devType: "vxlan"},
		{name: "docker0", devType: "bridge"},
		{name: "team0"},
		{name: "vrf0", devType: "vrf"},
		{name: "ovsbr0", devType: "openvswitch"},
		{name: "dummy0"},
		{name: "unheardof0", devType: "somethingnew"},
		{name: "plainsysfs0", plainDir: true},
		// A hardware name the kernel files under the virtual tree, stacked on
		// its peer: this is what the interface of a container looks like from
		// inside it.
		{name: "eth1", stacked: true},
		{name: "veth9f2a1c", stacked: true},
		{name: "veth2b3c4d", devType: "veth"},
		{name: "cali1a2b3c4d5e6", stacked: true},
		{name: "macvlan0", devType: "macvlan"},
		{name: "macvlan1", stacked: true},
		{name: "ipvlan0", devType: "ipvlan"},
		{name: "tap0", tunFlags: true},
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
		{name: "a bridge is reported", iface: "br0", reported: true},
		{name: "a bridge with no device type is reported", iface: "br1", reported: true},
		{name: "a bond is reported", iface: "bond0", reported: true},
		{name: "a vlan is reported", iface: "eth0.100", reported: true},
		{name: "a vxlan is reported", iface: "vxlan0", reported: true},
		// The kind decides, not the name: a bridge a container runtime created
		// is a bridge like any other.
		{name: "a container runtime bridge is reported", iface: "docker0", reported: true},
		{name: "a team is reported", iface: "team0", reported: true},
		{name: "a vrf master is reported", iface: "vrf0", reported: true},
		{name: "an open vswitch bridge is reported", iface: "ovsbr0", reported: true},
		{name: "a dummy interface is reported", iface: "dummy0", reported: true},
		// The kinds that are left out are named one by one, so a kind this
		// package has never heard of is reported rather than dropped.
		{name: "an unrecognised kind is reported", iface: "unheardof0", reported: true},
		{name: "an entry that is not a symlink is reported", iface: "plainsysfs0", reported: true},
		{name: "the interface of a container is left out", iface: "eth1"},
		{name: "one half of a veth pair is left out", iface: "veth9f2a1c"},
		{name: "a veth half the kernel names is left out", iface: "veth2b3c4d"},
		{name: "a container network device is left out", iface: "cali1a2b3c4d5e6"},
		// Whether the kernel records a device type for a macvlan child makes no
		// difference: what it is stacked on says the same thing.
		{name: "a macvlan child is left out", iface: "macvlan0"},
		{name: "a macvlan child with no device type is left out", iface: "macvlan1"},
		{name: "an ipvlan child is left out", iface: "ipvlan0"},
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
		{
			name:     "an include list of everything reports a veth half anyway",
			iface:    "veth9f2a1c",
			include:  []string{"*"},
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

// A machine can have nothing but interfaces of the kinds that are left out. Its
// report is the interfaces it has, never an empty one, which on the receiving
// side reads as the machine having lost them.
func TestReportableInterfacesOnAMachineWithOnlyExcludedKinds(t *testing.T) {
	useSysClassNet(t, writeSysClassNet(t, []ifaceFixture{
		{name: "eth0", stacked: true},
		{name: "lo"},
	}))

	reported := reportableInterfaces([]Iface{
		{Name: "eth0", Mac: testMAC},
		{Name: "lo", Mac: "00:00:00:00:00:00", Loopback: true},
	}, nil)

	assert.Equal(t, map[string]bool{"eth0": true}, reported,
		"the interface is reported although its kind is one that is left out, and loopback still is not")
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
