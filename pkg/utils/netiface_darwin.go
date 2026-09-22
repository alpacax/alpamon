package utils

// platformVirtualIfacePrefixes names the virtual interfaces macOS creates:
// utun for tunnels, awdl and llw for peer-to-peer wireless, bridge for the
// software bridge, anpi and ap for the interfaces of the built-in
// coprocessors. They are matched only here, since on another platform the same
// prefixes could belong to hardware.
var platformVirtualIfacePrefixes = []string{
	"utun",
	"awdl",
	"llw",
	"bridge",
	"anpi",
	"ap",
}

// interfaceKind reports no kind on macOS, which leaves the name pattern above
// to decide. A detector that reads the kind from the routing socket would
// replace this function and nothing else: the predicate, the include list and
// the callers are shared with the platform that has one.
func interfaceKind(_ string) ifaceKind {
	return kindUnknown
}
