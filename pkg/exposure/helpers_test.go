package exposure

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// fixturesDir holds the wire contract's goldens, shared with the server.
const fixturesDir = "../../testdata/exposure"

// updateGolden regenerates the goldens instead of checking them.
var updateGolden = os.Getenv("EXPOSURE_UPDATE_GOLDEN") == "1"

// assertClosedReasons fails when a body carries a reason code outside the
// agent's closed list or a coverage status outside its enum.
func assertClosedReasons(t *testing.T, body []byte) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var tree any
	require.NoError(t, dec.Decode(&tree))
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if k == "reasons" {
					list, ok := e.([]any)
					require.True(t, ok, "reasons is not a list")
					for _, r := range list {
						s, _ := r.(string)
						require.True(t, agentReasons[s], "reason %q is not an agent reason", s)
					}
				}
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(tree)
}

// mapSource is a systemSource over in-memory files for parser tests.
type mapSource struct {
	files map[string]string
	dirs  map[string][]string
	// status overrides a path's read status.
	status map[string]string
}

func (m mapSource) load(p string) loaded {
	if st, ok := m.status[p]; ok {
		l := loaded{status: st, reasons: reasonSet{}}
		switch st {
		case statusUnreadable:
			l.reasons.add(reasonFileUnreadable)
		case statusRejected:
			l.reasons.add(reasonFileRejected)
		}
		return l
	}
	data, ok := m.files[p]
	if !ok {
		return loaded{status: statusAbsent, reasons: reasonSet{}}
	}
	return loaded{status: statusRead, reasons: reasonSet{}, data: []byte(data)}
}

func (m mapSource) list(p string) ([]string, loaded) {
	names, ok := m.dirs[p]
	if !ok {
		return nil, loaded{status: statusAbsent, reasons: reasonSet{}}
	}
	return names, loaded{status: statusRead, reasons: reasonSet{}, data: []byte{}}
}
