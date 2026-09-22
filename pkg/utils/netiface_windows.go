package utils

// platformVirtualIfacePrefixes names the virtual adapters Windows creates, by
// the start of the adapter name it reports for them. They are matched only
// here, since on another platform the same prefixes could belong to hardware.
var platformVirtualIfacePrefixes = []string{
	"Loopback",
	"isatap",
	"Teredo",
	"6to4",
}

// interfaceKind reports no kind on Windows, which leaves the name pattern above
// to decide. A detector that reads the interface type from the adapter table
// would replace this function and nothing else: the predicate, the include list
// and the callers are shared with the platform that has one.
func interfaceKind(_ string) ifaceKind {
	return kindUnknown
}
