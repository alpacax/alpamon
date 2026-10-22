package runner

// peerCred is what the kernel reports about the process on the other end of
// auth.sock. pid is meaningful only when pidKnown is true.
type peerCred struct {
	uid      int
	pid      int
	pidKnown bool
}

// peerUIDAllowed admits root and the agent's own user: with the socket at 0600,
// they are the only users the kernel lets connect anyway.
func peerUIDAllowed(uid, selfEUID int) bool {
	return uid == 0 || uid == selfEUID
}
