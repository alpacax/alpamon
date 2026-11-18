package runner

func newProcessControl(cancel func(commandID string)) WorkSessionProcessController {
	return cancelProcessControl{cancel: cancel}
}

// ownedSessionAlive is false: Windows tracks no process sessions.
func ownedSessionAlive(OwnedSession) bool {
	return false
}

func processStartedAt(int) int64 {
	return 0
}

// pinSession does nothing: Windows tracks no process sessions.
func pinSession(OwnedSession) {}

// adoptSession does nothing: Windows tracks no process sessions.
func adoptSession(OwnedSession) {}
