package shell

import "strings"

const shellWhitespace = " \t\n\r"

// unwrapNestedPowerShell converts a nested `powershell -Command <script>` command into direct argv so its embedded quotes are parsed once instead of being corrupted by the outer wrapper's second parse.
func unwrapNestedPowerShell(command string) ([]string, bool) {
	exe, rest := splitToken(strings.TrimLeft(command, shellWhitespace))
	switch strings.ToLower(exe) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
	default:
		return nil, false
	}

	result := []string{exe}
	for {
		rest = strings.TrimLeft(rest, shellWhitespace)
		if rest == "" {
			break
		}

		token, remainder := splitToken(rest)
		if strings.ContainsAny(token, `"'`) {
			return nil, false
		}

		if isCommandFlag(token) {
			tail := strings.TrimLeft(remainder, shellWhitespace)
			if tail == "" || tail == "-" {
				return nil, false
			}
			return append(result, "-Command", tail), true
		}
		switch strings.ToLower(token) {
		case "-file", "-encodedcommand", "-e", "-ec":
			return nil, false
		}

		result = append(result, token)
		rest = remainder
	}

	return nil, false
}

// splitToken returns the first whitespace-delimited token and the untrimmed remainder.
func splitToken(s string) (token, rest string) {
	if i := strings.IndexAny(s, shellWhitespace); i != -1 {
		return s[:i], s[i:]
	}
	return s, ""
}

// isCommandFlag matches -Command, its -c shorthand, and unambiguous prefixes (-com and longer); -co is rejected as ambiguous with -ConfigurationName.
func isCommandFlag(token string) bool {
	t := strings.ToLower(token)
	if t == "-c" {
		return true
	}
	return len(t) >= len("-com") && strings.HasPrefix("-command", t)
}
