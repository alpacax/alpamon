package runner

// CapabilityFileExec names the verified file lane: commands with shell "file".
const CapabilityFileExec = "file_exec"

// agentCapabilities lists the execution lanes compiled into this build, for
// the capabilities key of the commit and the server sync. It is decided by
// build constraints, never by the version string, and is never nil, so the key
// always marshals as a list.
func agentCapabilities() []string {
	capabilities := []string{}
	if fileExecCompiled {
		capabilities = append(capabilities, CapabilityFileExec)
	}
	return capabilities
}
