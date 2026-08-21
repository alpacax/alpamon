package runner

import "errors"

// errSealUnavailable marks a host that cannot give the agent an execution
// object beyond the requester's reach. Executing the on-disk inode instead is
// not an acceptable fallback—that is the very window the sealed copy closes—so
// a file command refuses here.
var errSealUnavailable = errors.New("no tamper-proof execution object is available")
