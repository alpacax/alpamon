package runner

const maxCheckedSudo = 4096

// Never skip the password if a later approval could lose its positive check.
func (am *AuthManager) rememberCheckedSudoLocked(pid int, start uint64, lookup func(int) (uint64, bool)) bool {
	if start == 0 {
		return false
	}
	if am.checkedSudo == nil {
		am.checkedSudo = make(map[int]uint64)
	}
	if _, exists := am.checkedSudo[pid]; !exists && len(am.checkedSudo) >= maxCheckedSudo {
		for key, recorded := range am.checkedSudo {
			current, absent := lookup(key)
			if absent || current != 0 && current != recorded {
				delete(am.checkedSudo, key)
				break
			}
		}
		if len(am.checkedSudo) >= maxCheckedSudo {
			return false
		}
	}
	am.checkedSudo[pid] = start
	return true
}

func (am *AuthManager) wasCheckedSudoLocked(pid int, start uint64) bool {
	recorded, ok := am.checkedSudo[pid]
	if !ok {
		return false
	}
	if start == 0 {
		// An unreadable timestamp cannot establish PID reuse. Keep the check
		// for a retry and require session approval on this request.
		return true
	}
	if start != recorded {
		delete(am.checkedSudo, pid)
		return false
	}
	return true
}
