package exposure

import (
	"bytes"
	"slices"
	"time"
)

// Bounds on the work one read may do. Each is checked before the memory it
// guards is allocated.
const (
	maxReadBytes          = 1 << 20 // a read stops at this plus one byte
	maxLineBytes          = 16 << 10
	maxKeysPerAccount     = 1000
	maxAccounts           = 2000
	maxIncludeDepth       = 8
	maxIncludeFiles       = 128
	maxReportBytes        = 2 << 20
	maxAccountBytes       = 256 << 10
	maxTrustEntries       = 256
	maxMatchBlocks        = 256
	maxExternalRecords    = 256
	maxConcurrentAccounts = 4
	accountReturnMargin   = 250 * time.Millisecond
	maxAccountWorkers     = 16 // abandoned workers, in addition to the category lanes
	accountBudget         = 2 * time.Second
	maxDirEntries         = 4096
	maxCommentRunes       = 128
	maxFromBytes          = 1024
	maxPrincipals         = 64
	maxPrincipalEntries   = 256
	maxCommandPaths       = 32
	maxEffectiveValueLen  = 8 << 10
	maxGroupsPerAccount   = 1024

	categoryBudget = 10 * time.Second
	sshdTimeout    = 5 * time.Second
	sshdStdoutCap  = 256 << 10
)

// reasonSet collects reason codes; list returns them sorted.
type reasonSet map[string]struct{}

func (s reasonSet) add(codes ...string) {
	for _, c := range codes {
		s[c] = struct{}{}
	}
}

func (s reasonSet) merge(o reasonSet) {
	for c := range o {
		s[c] = struct{}{}
	}
}

func (s reasonSet) has(c string) bool {
	_, ok := s[c]
	return ok
}

func (s reasonSet) list() []string {
	out := make([]string, 0, len(s))
	for c := range s {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

// forEachLine calls fn for every line of data with any trailing CR removed.
// A line longer than maxLineBytes is reported with tooLong set and no
// content, so a caller can count it without looking at it.
func forEachLine(data []byte, fn func(line []byte, tooLong bool) bool) {
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		if len(line) > maxLineBytes {
			if !fn(nil, true) {
				return
			}
			continue
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if !fn(line, false) {
			return
		}
	}
}

// isBlankOrComment reports whether a configuration line carries nothing.
func isBlankOrComment(line []byte) bool {
	t := bytes.TrimLeft(line, " \t\v\f\r")
	return len(bytes.TrimSpace(line)) == 0 || len(t) > 0 && t[0] == '#'
}

func ptr[T any](v T) *T { return &v }

func appendReason(reasons []string, code string) []string {
	set := reasonSet{}
	set.add(reasons...)
	set.add(code)
	return set.list()
}
