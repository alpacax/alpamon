package utils

import (
	"path"
	"strings"

	"github.com/shirou/gopsutil/v4/net"

	"github.com/alpacax/alpamon/v2/pkg/config"
)

// Interface reporting.
//
// The agent reports the interfaces an operator would call the machine's own:
// the ones backed by hardware, and the links an operator configures on top of
// them. The devices a running system mints for itself, one per container, per
// tunnel or per sandbox, are left out of both the inventory and the traffic
// counters.
//
// An interface is classified by its link kind wherever the platform exposes
// one, and by its name only where it does not. A name carries very little: the
// naming schemes container runtimes use are theirs to change, so a prefix list
// written against them both misses names it has never seen and, as soon as one
// entry is also the start of a hardware name, claims interfaces that are real.
//
// Both call sites go through ReportableInterface, so the set of interfaces in
// the inventory and the set the traffic counters cover cannot drift apart.

// ifaceKind is what the platform's detector could establish about an interface.
type ifaceKind int

const (
	// kindUnknown means the platform exposes no link kind for the interface,
	// so its name is all there is to go on.
	kindUnknown ifaceKind = iota
	// kindHardware means the interface is backed by a hardware device.
	kindHardware
	// kindConfiguredVirtual means the interface is virtual and of a kind an
	// operator configures on the host, so the agent reports it unasked.
	kindConfiguredVirtual
	// kindVirtual means the interface is virtual and of a kind the agent
	// reports only when the include list names it.
	kindVirtual
)

// commonVirtualIfacePrefixes names the virtual interfaces that carry the same
// names on every platform the agent builds for. Entries are matched as
// prefixes and nothing more, so an entry must not also be the start of a
// hardware interface name. Platform-specific names belong in the
// platformVirtualIfacePrefixes of the platform that uses them.
//
// This list decides only where no link kind is available. On a platform that
// reports one, it is the fallback for an interface the platform has nothing to
// say about.
var commonVirtualIfacePrefixes = []string{
	"docker",
	"veth",
	"br-",
	"virbr",
	"vmnet",
	"tap",
	"tun",
	"wg",
	"zt",
	"tailscale",
	"cni",
}

// loopbackFlag is how the flag sets this package is handed spell loopback.
const loopbackFlag = "loopback"

// ReportableInterface reports whether an interface belongs in what the agent
// reports. Each caller adapts its own interface type to it: loopback is the
// interface's loopback flag, read from whichever flag representation the
// caller's source gives it, and mac is its hardware address, empty when it has
// none.
func ReportableInterface(name, mac string, loopback bool) bool {
	return reportableInterface(name, mac, loopback, config.GlobalSettings.IncludeVirtualInterfaces)
}

// reportableInterface is ReportableInterface with the include list passed in.
func reportableInterface(name, mac string, loopback bool, include []string) bool {
	// Loopback is not an interface of the machine's, and an interface with no
	// hardware address has nothing to identify it by. Neither is recoverable
	// through the include list.
	if loopback || mac == "" {
		return false
	}

	if matchesInterfacePattern(include, name) {
		return true
	}

	return !isUnreportedVirtual(name)
}

// isUnreportedVirtual reports whether an interface is virtual and of a kind the
// agent leaves out unless the configuration asks for it.
func isUnreportedVirtual(name string) bool {
	switch interfaceKind(name) {
	case kindHardware, kindConfiguredVirtual:
		return false
	case kindVirtual:
		return true
	default:
		// The platform reports no kind for this interface, so the name is all
		// there is. A name the prefixes do not claim is reported: reporting one
		// interface too many is the recoverable error, since the include list
		// can only add interfaces back, not take them away.
		return hasVirtualIfacePrefix(name)
	}
}

// hasVirtualIfacePrefix reports whether a name starts with one of the prefixes
// that belong to virtual interfaces on this platform.
func hasVirtualIfacePrefix(name string) bool {
	for _, prefix := range commonVirtualIfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	for _, prefix := range platformVirtualIfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}

// matchesInterfacePattern reports whether an interface name matches one of the
// configured patterns. A pattern is an exact name or a glob in the syntax of
// path.Match. The name is compared as itself first, so a pattern that path.Match
// cannot parse still names the interface spelled exactly that way; the
// configuration reports and drops such patterns when it reads them.
func matchesInterfacePattern(patterns []string, name string) bool {
	for _, pattern := range patterns {
		if pattern == name {
			return true
		}

		if matched, err := path.Match(pattern, name); err == nil && matched {
			return true
		}
	}

	return false
}

// FilterVirtualInterface returns the interfaces the agent reports, keyed by
// name.
func FilterVirtualInterface(ifaces net.InterfaceStatList) map[string]net.InterfaceStat {
	interfaces := make(map[string]net.InterfaceStat)
	for _, iface := range ifaces {
		if !ReportableInterface(iface.Name, iface.HardwareAddr, hasLoopbackFlag(iface.Flags)) {
			continue
		}

		interfaces[iface.Name] = iface
	}

	return interfaces
}

// hasLoopbackFlag reports whether a flag set spelled out as strings carries the
// loopback flag.
func hasLoopbackFlag(flags []string) bool {
	for _, flag := range flags {
		if strings.EqualFold(flag, loopbackFlag) {
			return true
		}
	}

	return false
}
