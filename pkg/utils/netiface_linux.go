package utils

import (
	"os"
	"path/filepath"
	"strings"
)

// sysClassNet is the sysfs directory describing the network interfaces of the
// current network namespace. It is a variable so that tests can point the
// detector at a fixture tree.
var sysClassNet = "/sys/class/net"

// virtualNetPath is the part of a sysfs path that says the kernel created the
// interface itself rather than for a device on a bus.
const virtualNetPath = "/devices/virtual/net/"

// platformVirtualIfacePrefixes is empty on Linux: the kind comes from sysfs,
// and the shared prefixes are only the fallback for an interface sysfs has
// nothing to say about.
var platformVirtualIfacePrefixes []string

// configuredVirtualDevTypes are the sysfs device types of the virtual link
// kinds the agent reports unasked. They are the links an operator configures
// for the host to use, rather than the ones a container runtime or a tunnel
// creates for itself.
var configuredVirtualDevTypes = map[string]bool{
	"bridge": true,
	"bond":   true,
	"vlan":   true,
	"vxlan":  true,
}

// configuredVirtualMarkerDirs are directories sysfs creates under an interface
// whose kind carries settings of its own. They stand in for the device type on
// a kernel that records none for that kind.
var configuredVirtualMarkerDirs = []string{
	"bridge",
	"bonding",
}

// interfaceKind reads the link kind of an interface from sysfs.
func interfaceKind(name string) ifaceKind {
	// The name comes from the operating system, but a path is built from it, so
	// anything that is not a single path element is refused rather than
	// resolved.
	if name == "" || name == "." || name == ".." || name != filepath.Base(name) {
		return kindUnknown
	}

	dir := filepath.Join(sysClassNet, name)
	if _, err := os.Lstat(dir); err != nil {
		// Either /sys is not mounted or the interface went away between the
		// listing and this call.
		return kindUnknown
	}

	// An interface backed by hardware carries a device symlink to the bus
	// device that drives it, and sysfs files it under that device rather than
	// under the virtual tree. Either answer is taken as hardware: leaving out a
	// hardware interface is the error the configuration cannot undo.
	if _, err := os.Lstat(filepath.Join(dir, "device")); err == nil {
		return kindHardware
	}

	if target, err := os.Readlink(dir); err == nil &&
		!strings.Contains(filepath.ToSlash(target), virtualNetPath) {
		return kindHardware
	}

	if devType := sysfsDevType(dir); devType != "" {
		if configuredVirtualDevTypes[devType] {
			return kindConfiguredVirtual
		}

		// A kind the kernel names and this list does not hold, such as a
		// macvlan or an ipvlan child, is reported only when the include list
		// asks for it. Deciding on the device type rather than on how the
		// interface is wired gives the same answer whether or not the running
		// kernel records one for that kind.
		return kindVirtual
	}

	for _, marker := range configuredVirtualMarkerDirs {
		if info, err := os.Stat(filepath.Join(dir, marker)); err == nil && info.IsDir() {
			return kindConfiguredVirtual
		}
	}

	return kindVirtual
}

// sysfsDevType returns the device type the kernel records for an interface, or
// an empty string when it records none.
func sysfsDevType(dir string) string {
	uevent, err := os.ReadFile(filepath.Join(dir, "uevent"))
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(uevent), "\n") {
		if devType, found := strings.CutPrefix(strings.TrimSpace(line), "DEVTYPE="); found {
			return strings.TrimSpace(devType)
		}
	}

	return ""
}
