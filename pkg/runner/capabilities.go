package runner

// capabilityFileExec names the verified file lane: commands with shell "file".
const capabilityFileExec = "file_exec"

// agentCapabilities lists the execution lanes compiled into this build, then
// the control protocols every build speaks. Build constraints decide it,
// never the version string, and it is never nil, so the key always marshals
// as a list.
func agentCapabilities() []string {
	capabilities := []string{}
	if fileExecCompiled {
		capabilities = append(capabilities, capabilityFileExec)
	}
	return append(capabilities, capabilityWorkSessionControl)
}
