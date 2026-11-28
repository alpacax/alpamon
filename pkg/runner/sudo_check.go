package runner

import "time"

const (
	sudoCheckTTL   = 120 * time.Second
	maxCheckedSudo = 4096
)

type checkedSudoProcess struct {
	start   uint64
	expires time.Time
}

// Never skip the password if a later approval could lose its positive check.
func (am *AuthManager) rememberCheckedSudoLocked(pid int, start uint64, now time.Time) bool {
	if start == 0 {
		return false
	}
	if am.checkedSudo == nil {
		am.checkedSudo = make(map[int]checkedSudoProcess)
	}
	if _, exists := am.checkedSudo[pid]; !exists && len(am.checkedSudo) >= maxCheckedSudo {
		for key, check := range am.checkedSudo {
			if !now.Before(check.expires) {
				delete(am.checkedSudo, key)
			}
		}
		if len(am.checkedSudo) >= maxCheckedSudo {
			return false
		}
	}
	am.checkedSudo[pid] = checkedSudoProcess{start: start, expires: now.Add(sudoCheckTTL)}
	return true
}

func (am *AuthManager) consumeCheckedSudoLocked(pid int, start uint64, now time.Time) bool {
	check, ok := am.checkedSudo[pid]
	if !ok {
		return false
	}
	if !now.Before(check.expires) {
		delete(am.checkedSudo, pid)
		return false
	}
	if start == 0 {
		// An unreadable timestamp cannot establish PID reuse. Keep the check
		// for a retry and require session approval on this request.
		return true
	}
	if start != check.start {
		return false
	}
	delete(am.checkedSudo, pid)
	return true
}
