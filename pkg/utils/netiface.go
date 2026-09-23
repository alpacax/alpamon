package utils

import (
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/alpacax/alpamon/v2/pkg/config"
)

// Interface reporting.
//
// The agent reports two things about a machine's network interfaces: which
// interfaces it has, and how much traffic each of them carries. The two are
// reported to different ends and are filtered differently.
//
// The interface list is an inventory. An interface that drops out of it is
// read on the other side as an interface the machine no longer has, and what
// the other side then does with the rows it holds is not this agent's to
// decide. So the inventory filter is the one the agent has always applied, a
// list of name prefixes, and nothing here narrows it: an agent that upgrades
// reports the interfaces it reported yesterday.
//
// Traffic is a measurement, and an interface that stops sending samples simply
// stops charting. That is where the kinds a running system creates one of per
// container or per connection are left out: a veth half, a macvlan or ipvlan
// child, a tun or tap device. Their inventory rows stay where they are.
//
// An operator who knows the other side keeps a removed interface can narrow
// the inventory the same way with exclude_virtual_from_inventory. That setting
// is the only one here that depends on what the other side does.
//
// Where a kind is read at all is per platform: Linux reads it from sysfs,
// macOS and Windows expose none and fall back to the name prefixes, so on
// those platforms traffic covers exactly the interfaces the inventory does.

// ifaceKind is what the platform's detector could establish about an interface.
type ifaceKind int

const (
	// kindUnknown means the platform exposes no link kind for the interface,
	// so its name is all there is to go on.
	kindUnknown ifaceKind = iota
	// kindHardware means the interface is backed by a hardware device.
	kindHardware
	// kindVirtual means the interface is virtual and of a kind that is
	// reported, which is every kind not named as one that is left out.
	kindVirtual
	// kindExcludedVirtual means the interface is virtual and of one of the
	// kinds that are left out, so it is reported only when the include list
	// names it.
	kindExcludedVirtual
)

// virtualIfacePattern is the inventory filter, and it is frozen. It is the
// pattern the agent has always applied, and narrowing it would take interfaces
// out of an inventory that has been reporting them.
//
// Matched by prefix and nothing more, so an entry must not also be a prefix
// of a physical interface name. systemd predictable names such as enp0s3 and
// enp0s31f6 belong to physical NICs on PCI bus 0, so no enp prefix goes here.
var virtualIfacePattern = regexp.MustCompile(`^(lo|docker|veth|br-|virbr|vmnet|tap|tun|wg|zt|tailscale|cni|utun|awdl|llw|bridge|anpi|ap|Loopback|isatap|Teredo|6to4)`)

// commonVirtualIfacePrefixes names the interfaces that are virtual under the
// same names on every platform the agent builds for. Entries are matched as
// prefixes and nothing more, so an entry must not also be the start of a
// hardware interface name. Platform-specific names belong in the
// platformVirtualIfacePrefixes of the platform that uses them.
//
// This is the fallback for the kind, not the inventory filter above, and the
// two are deliberately separate: this one is consulted only where no link kind
// is available, and it is free to change as the kinds it stands in for do.
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

// emptyTrafficOnce keeps the fallback in byKindInterfaces to one log line per
// run.
var emptyTrafficOnce sync.Once

// Iface is what the report predicates read from an interface. Each caller
// adapts its own interface type to it: Mac is the hardware address, empty when
// the interface has none, and Loopback is the loopback flag as the caller's own
// flag representation gives it.
type Iface struct {
	Name     string
	Mac      string
	Loopback bool
}

// InventoryInterfaces returns the names of the interfaces to report as the
// machine's own, out of everything the operating system listed.
func InventoryInterfaces(ifaces []Iface) map[string]bool {
	return inventoryInterfaces(ifaces, config.GlobalSettings.IncludeVirtualInterfaces,
		config.GlobalSettings.ExcludeVirtualFromInventory)
}

// TrafficInterfaces returns the names of the interfaces to report traffic for.
// It is what the inventory reports, less the kinds that are left out, so no
// traffic is ever reported for an interface the inventory does not carry.
func TrafficInterfaces(ifaces []Iface) map[string]bool {
	return trafficInterfaces(ifaces, config.GlobalSettings.IncludeVirtualInterfaces,
		config.GlobalSettings.ExcludeVirtualFromInventory)
}

// inventoryInterfaces is InventoryInterfaces with the configuration passed in.
func inventoryInterfaces(ifaces []Iface, include []string, byKind bool) map[string]bool {
	if byKind {
		return byKindInterfaces(ifaces, include)
	}

	return byNameInterfaces(ifaces, include)
}

// trafficInterfaces is TrafficInterfaces with the configuration passed in.
func trafficInterfaces(ifaces []Iface, include []string, byKind bool) map[string]bool {
	if byKind {
		// The inventory already leaves out the kinds that are left out here,
		// and traffic covers what the inventory holds.
		return byKindInterfaces(ifaces, include)
	}

	inventory := byNameInterfaces(ifaces, include)

	listed := make([]Iface, 0, len(inventory))
	for _, iface := range ifaces {
		if inventory[iface.Name] {
			listed = append(listed, iface)
		}
	}

	return byKindInterfaces(listed, include)
}

// byNameInterfaces returns the interfaces the name pattern reports. An
// interface with no hardware address is left out, since the report identifies
// an interface by it; the include list names the interfaces to report despite
// the pattern, and cannot name loopback.
func byNameInterfaces(ifaces []Iface, include []string) map[string]bool {
	reported := make(map[string]bool, len(ifaces))
	for _, iface := range ifaces {
		if iface.Mac == "" {
			continue
		}

		switch {
		case !virtualIfacePattern.MatchString(iface.Name):
			reported[iface.Name] = true
		case !iface.Loopback && matchesInterfacePattern(include, iface.Name):
			reported[iface.Name] = true
		}
	}

	return reported
}

// byKindInterfaces returns the interfaces whose link kind is one that is
// reported. It takes a whole listing rather than one interface at a time
// because of the last rule it applies: where that would leave nothing at all,
// the interfaces it left out are reported after all.
func byKindInterfaces(ifaces []Iface, include []string) map[string]bool {
	reported := make(map[string]bool, len(ifaces))
	excluded := []string{}

	for _, iface := range ifaces {
		if reportableInterface(iface.Name, iface.Mac, iface.Loopback, include) {
			reported[iface.Name] = true
			continue
		}

		// Loopback and an interface with no hardware address are left out
		// whatever else is true of them, so they are not candidates below.
		if !iface.Loopback && iface.Mac != "" {
			excluded = append(excluded, iface.Name)
		}
	}

	if len(reported) > 0 || len(excluded) == 0 {
		return reported
	}

	// A machine can legitimately have only interfaces of the kinds this
	// package leaves out: one running inside a container has a single veth
	// half and nothing else. Reporting nothing for it would read as a machine
	// with no traffic at all rather than as a machine whose traffic is carried
	// on a kind that is usually noise, so the kinds are reported after all.
	emptyTrafficOnce.Do(func() {
		log.Warn().Msgf("Every interface of this machine is of a kind that is usually left out of "+
			"traffic reporting; reporting %s so that no traffic is reported for none of them.",
			strings.Join(excluded, ", "))
	})

	for _, name := range excluded {
		reported[name] = true
	}

	return reported
}

// reportableInterface reports whether an interface's link kind is one that is
// reported, leaving aside the rule that the set is never empty.
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

	return !isExcludedVirtual(name)
}

// isExcludedVirtual reports whether an interface is virtual and of one of the
// kinds that are left out unless the configuration asks for them.
func isExcludedVirtual(name string) bool {
	switch interfaceKind(name) {
	case kindHardware, kindVirtual:
		return false
	case kindExcludedVirtual:
		return true
	default:
		// The platform reports no kind for this interface, so the name is all
		// there is. A name the prefixes do not claim is reported.
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

// FilterVirtualInterface returns the interfaces to report traffic for, keyed by
// name.
func FilterVirtualInterface(ifaces net.InterfaceStatList) map[string]net.InterfaceStat {
	listed := make([]Iface, 0, len(ifaces))
	for _, iface := range ifaces {
		listed = append(listed, Iface{
			Name:     iface.Name,
			Mac:      iface.HardwareAddr,
			Loopback: hasLoopbackFlag(iface.Flags),
		})
	}

	reported := TrafficInterfaces(listed)

	interfaces := make(map[string]net.InterfaceStat, len(reported))
	for _, iface := range ifaces {
		if !reported[iface.Name] {
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
