package common

// HandlerType represents the type of a handler
type HandlerType string

// CommandType represents the type of a command
type CommandType string

// Handler type constants
const (
	System       HandlerType = "system"
	Group        HandlerType = "group"
	Info         HandlerType = "info"
	Shell        HandlerType = "shell"
	User         HandlerType = "user"
	Firewall     HandlerType = "firewall"
	FileTransfer HandlerType = "file"
	Terminal     HandlerType = "terminal"
)

// Command type constants
const (
	// System commands
	Upgrade  CommandType = "upgrade"
	Restart  CommandType = "restart"
	Quit     CommandType = "quit"
	Reboot   CommandType = "reboot"
	Shutdown CommandType = "shutdown"
	Update   CommandType = "update"
	ByeBye   CommandType = "byebye"

	// Group commands
	AddGroup CommandType = "addgroup"
	DelGroup CommandType = "delgroup"

	// Info commands
	Ping   CommandType = "ping"
	Help   CommandType = "help"
	Commit CommandType = "commit"
	Sync   CommandType = "sync"

	// Shell commands
	ShellCmd CommandType = "shell"
	Exec     CommandType = "exec"

	// User commands
	AddUser CommandType = "adduser"
	DelUser CommandType = "deluser"
	ModUser CommandType = "moduser"

	// Firewall commands
	FirewallCmd           CommandType = "firewall"
	FirewallRollback      CommandType = "firewall-rollback"
	FirewallReorderChains CommandType = "firewall-reorder-chains"
	FirewallReorderRules  CommandType = "firewall-reorder-rules"

	// Firewall sub-operations (used within firewall command)
	FirewallOpBatch  string = "batch"
	FirewallOpFlush  string = "flush"
	FirewallOpDelete string = "delete"
	FirewallOpAdd    string = "add"
	FirewallOpUpdate string = "update"

	// File commands
	Upload   CommandType = "upload"
	Download CommandType = "download"

	// Terminal commands
	OpenPty   CommandType = "openpty"
	OpenFtp   CommandType = "openftp"
	WritePty  CommandType = "writepty"
	ResizePty CommandType = "resizepty"
	ClosePty  CommandType = "closepty"
	CloseFtp  CommandType = "closeftp"
)

// Shell operators for command parsing
const (
	ShellAndOperator = "&&" // Execute next command only if previous succeeds
	ShellOrOperator  = "||" // Execute next command only if previous fails
	ShellSemicolon   = ";"  // Execute next command regardless of previous result
)

// String returns the string representation of HandlerType
func (h HandlerType) String() string {
	return string(h)
}

// String returns the string representation of CommandType
func (c CommandType) String() string {
	return string(c)
}

// CommandsToStrings converts a slice of CommandType to a slice of strings
func CommandsToStrings(commands []CommandType) []string {
	result := make([]string, len(commands))
	for i, cmd := range commands {
		result[i] = cmd.String()
	}
	return result
}
