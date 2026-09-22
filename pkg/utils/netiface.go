package utils

import (
	"path"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/alpacax/alpamon/v2/pkg/config"
)

// Interface reporting.
//
// The agent reports the interfaces of the machine it runs on: the ones backed
// by hardware, and the virtual links configured on top of them. What it leaves
// out is the handful of kinds a running system mints one of per container or
// per tunnel, which say nothing about the machine and arrive in numbers.
//
// An interface is classified by its link kind wherever the platform exposes
// one, and by its name only where it does not. A name carries very little: the
// naming schemes container runtimes use are theirs to change, so a prefix list
// written against them both misses names it has never seen and, as soon as one
// entry is also the start of a hardware name, claims interfaces that are real.
//
// Both ways of being wrong are not equal. An interface the agent reports and
// should not is a row too many, which a setting can take away. An interface it
// stops reporting is read on the other side as an interface that has gone, so
// the kinds left out are named one by one and anything unrecognised is
// reported. For the same reason a report is never empty: see
// ReportableInterfaces.
//
// Every caller goes through ReportableInterfaces, so the set of interfaces in
// the inventory and the set the traffic counters cover cannot drift apart.

// ifaceKind is what the platform's detector could establish about an interface.
type ifaceKind int

const (
	// kindUnknown means the platform exposes no link kind for the interface,
	// so its name is all there is to go on.
	kindUnknown ifaceKind = iota
	// kindHardware means the interface is backed by a hardware device.
	kindHardware
	// kindVirtual means the interface is virtual and of a kind the agent
	// reports, which is every kind not named as one it leaves out.
	kindVirtual
	// kindExcludedVirtual means the interface is virtual and of one of the
	// kinds the agent leaves out, so it is reported only when the include list
	// names it.
	kindExcludedVirtual
)

// commonVirtualIfacePrefixes names the interfaces that are virtual under the
// same names on every platform the agent builds for. Entries are matched as
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

// emptyReportOnce keeps the fallback below to one log line per run.
var emptyReportOnce sync.Once

// Iface is what the report predicate reads from an interface. Each caller
// adapts its own interface type to it: Mac is the hardware address, empty when
// the interface has none, and Loopback is the loopback flag as the caller's own
// flag representation gives it.
type Iface struct {
	Name     string
	Mac      string
	Loopback bool
}

// ReportableInterfaces returns the names of the interfaces to report, out of
// everything the operating system listed. It takes the whole listing rather
// than one interface at a time because of the last rule it applies: a machine
// whose every interface is of a kind the agent leaves out reports those
// interfaces anyway.
func ReportableInterfaces(ifaces []Iface) map[string]bool {
	return reportableInterfaces(ifaces, config.GlobalSettings.IncludeVirtualInterfaces)
}

// reportableInterfaces is ReportableInterfaces with the include list passed in.
func reportableInterfaces(ifaces []Iface, include []string) map[string]bool {
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

	// Nothing is left to report. A machine can legitimately have only
	// interfaces of the kinds this package leaves out—one running inside a
	// container has a single veth half and nothing else—and an empty report is
	// not a smaller report: it is read on the other side as every interface of
	// this machine having gone away. Reporting them is the lesser error, and
	// the include list can still narrow what is reported.
	emptyReportOnce.Do(func() {
		log.Warn().Msgf("Every interface of this machine is of a kind that is not reported; "+
			"reporting %s so the report is not empty.", strings.Join(excluded, ", "))
	})

	for _, name := range excluded {
		reported[name] = true
	}

	return reported
}

// reportableInterface reports whether an interface belongs in what the agent
// reports, leaving aside the rule that a report is never empty.
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
// kinds the agent leaves out unless the configuration asks for it.
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

// FilterVirtualInterface returns the interfaces the agent reports, keyed by
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

	reported := ReportableInterfaces(listed)

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
