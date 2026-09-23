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

// excludedVirtualDevTypes are the sysfs device types of the virtual link kinds
// the agent leaves out: the ones a container runtime or a tunnel creates one of
// per container or per connection. Every other kind is reported, named or not,
// so a kind this list has never heard of is reported rather than dropped.
//
// Not every kernel records a device type for these. veth and macvlan record
// none on some kernels and are caught below by the device they are stacked on;
// dummy and ifb record none and no other marker distinguishes them, so there
// they are reported.
var excludedVirtualDevTypes = map[string]bool{
	"veth":    true,
	"macvlan": true,
	"ipvlan":  true,
	"tun":     true,
	"dummy":   true,
	"ifb":     true,
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
	// under the virtual tree.
	if _, err := os.Lstat(filepath.Join(dir, "device")); err == nil {
		return kindHardware
	}

	if target, err := os.Readlink(dir); err == nil &&
		!strings.Contains(filepath.ToSlash(target), virtualNetPath) {
		return kindHardware
	}

	// The kind the kernel names, where it names one. A vlan is stacked on
	// another interface the way a macvlan child is, so the device type is read
	// before anything is made of that.
	if devType := sysfsDevType(dir); devType != "" {
		if excludedVirtualDevTypes[devType] {
			return kindExcludedVirtual
		}

		return kindVirtual
	}

	// A tun or tap device, whose kind the kernel records nowhere else.
	if _, err := os.Lstat(filepath.Join(dir, "tun_flags")); err == nil {
		return kindExcludedVirtual
	}

	// An interface stacked on another one, with no device type to say which
	// kind it is: one half of a veth pair points at its peer, and a macvlan or
	// ipvlan child at the interface it was created on. A bridge, a bond, a team
	// or a dummy interface points at itself and is reported.
	if index, link, ok := sysfsLink(dir); ok && index != link {
		return kindExcludedVirtual
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

// sysfsLink returns an interface's own index and the index of the interface it
// is stacked on, which are the same number for an interface that stands on its
// own. The last return is false when sysfs gives neither.
func sysfsLink(dir string) (index string, link string, ok bool) {
	index = sysfsValue(dir, "ifindex")
	link = sysfsValue(dir, "iflink")

	return index, link, index != "" && link != ""
}

// sysfsValue returns the trimmed contents of one sysfs attribute, or an empty
// string when it cannot be read.
func sysfsValue(dir string, name string) string {
	value, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(value))
}
