package runner

// peerCred is what the kernel reports about the process on the other end of
// auth.sock. Only test stand-ins set skipPIDCheck, so a forgotten field keeps the check on.
type peerCred struct {
	uid          int
	pid          int
	skipPIDCheck bool
}

// peerUIDAllowed admits root and the agent's own user: with the socket no wider than 0600,
// they are the only users the kernel lets connect anyway.
func peerUIDAllowed(uid, selfEUID int) bool {
	return uid == 0 || uid == selfEUID
}
