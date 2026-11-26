package commandcancel

// HoldLeader is a no-op: Windows signals no process group.
func HoldLeader(int) {}

// ReapLeader runs reap.
func ReapLeader(_ int, reap func() error) error {
	return reap()
}
