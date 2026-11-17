package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// benignEnvKey is an admitted key that rides along with the key under test, so
// a refusal is shown to come from that key and not from the env as a whole.
const benignEnvKey = "FOO_BAR"

// commandEnvVectors mirrors testdata/command_env_policy_vectors.json. The
// server's copy of the list is tested against the same file.
type commandEnvVectors struct {
	Source         string   `json:"source"`
	Matching       string   `json:"matching"`
	Prefixes       []string `json:"prefixes"`
	ExactNames     []string `json:"exact_names"`
	RefusedKeys    []string `json:"refused_keys"`
	AdmittedKeys   []string `json:"admitted_keys"`
	MalformedKeys  []string `json:"malformed_keys"`
	RefusedValues  []string `json:"refused_values"`
	AdmittedValues []string `json:"admitted_values"`
}

// loadCommandEnvVectors decodes the shared vector file. Unknown fields fail the
// load, so a vector class added to the file cannot go unchecked here.
func loadCommandEnvVectors(t *testing.T) commandEnvVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "command_env_policy_vectors.json"))
	require.NoError(t, err)

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var vectors commandEnvVectors
	require.NoError(t, decoder.Decode(&vectors))

	for name, list := range map[string][]string{
		"prefixes":        vectors.Prefixes,
		"exact_names":     vectors.ExactNames,
		"refused_keys":    vectors.RefusedKeys,
		"admitted_keys":   vectors.AdmittedKeys,
		"malformed_keys":  vectors.MalformedKeys,
		"refused_values":  vectors.RefusedValues,
		"admitted_values": vectors.AdmittedValues,
	} {
		require.NotEmptyf(t, list, "vector list %s is empty", name)
	}
	return vectors
}

// titleCase uppercases the first byte of an ASCII key and lowercases the rest.
func titleCase(key string) string {
	if key == "" {
		return key
	}
	return strings.ToUpper(key[:1]) + strings.ToLower(key[1:])
}

func TestCommandEnvList_MatchesSharedVectors(t *testing.T) {
	vectors := loadCommandEnvVectors(t)

	assert.Equal(t, vectors.Prefixes, commandEnvPrefixes)
	assert.Equal(t, vectors.ExactNames, commandEnvExactNames)
}

func TestCheckCommandEnv_RefusesListedKeysInAnyCase(t *testing.T) {
	vectors := loadCommandEnvVectors(t)

	for _, key := range vectors.RefusedKeys {
		for _, variant := range []string{strings.ToUpper(key), strings.ToLower(key), titleCase(key)} {
			env := map[string]string{benignEnvKey: "value", variant: "value"}
			assert.Equalf(t, envDangerous, checkCommandEnv(env), "key %q", variant)
		}
	}
}

func TestCheckCommandEnv_AdmitsUnlistedKeys(t *testing.T) {
	vectors := loadCommandEnvVectors(t)

	assert.Equal(t, envAdmitted, checkCommandEnv(nil))
	for _, key := range vectors.AdmittedKeys {
		env := map[string]string{benignEnvKey: "value", key: "value"}
		assert.Equalf(t, envAdmitted, checkCommandEnv(env), "key %q", key)
	}
}

func TestCheckCommandEnv_RefusesMalformedKeys(t *testing.T) {
	vectors := loadCommandEnvVectors(t)

	for _, key := range vectors.MalformedKeys {
		env := map[string]string{benignEnvKey: "value", key: "value"}
		assert.Equalf(t, envMalformed, checkCommandEnv(env), "key %q", key)

		// A listed key alongside does not change the kind, whatever the map order.
		env["LD_PRELOAD"] = "value"
		assert.Equalf(t, envMalformed, checkCommandEnv(env), "key %q beside a listed key", key)
	}
}

func TestCheckCommandEnv_RefusesFunctionValuesUnderAnyKey(t *testing.T) {
	vectors := loadCommandEnvVectors(t)

	for _, value := range vectors.RefusedValues {
		env := map[string]string{benignEnvKey: value}
		assert.Equalf(t, envDangerous, checkCommandEnv(env), "value %q", value)
	}
}

func TestCheckCommandEnv_AdmitsOtherValues(t *testing.T) {
	vectors := loadCommandEnvVectors(t)

	for _, value := range vectors.AdmittedValues {
		env := map[string]string{benignEnvKey: value}
		assert.Equalf(t, envAdmitted, checkCommandEnv(env), "value %q", value)
	}
}

func TestCommandRunner_Run_ListedEnvKeyFinishesRefusedBeforeAnyShellRuns(t *testing.T) {
	// "file" carries no payload: had the env check not come first, the result
	// would be a file refusal instead of the env one.
	for _, shell := range []string{"system", "file"} {
		t.Run(shell, func(t *testing.T) {
			d := &cancelTestDispatcher{}
			wc, reports := cancelTestClient(t, d)

			wc.handleCommand(protocol.Command{
				ID:    "env-refused-" + shell,
				Shell: shell,
				Line:  "ping",
				User:  "root",
				Group: "root",
				Env:   map[string]string{benignEnvKey: "value", "LD_PRELOAD": "/tmp/preload.so"},
			}, protocol.CommandData{})

			report := receiveCancelReport(t, reports)
			assert.Equal(t, int32(0), d.calls.Load(), "a refused env must never reach a handler")
			assert.Equal(t, false, report["success"])
			assert.Equal(t, float64(1), report["exit_code"])
			assert.Equal(t, commandEnvRefusedResult, report["result"])
		})
	}
}

func TestCommandRunner_Run_InternalLaneIgnoresEnv(t *testing.T) {
	// The internal lane never applies a caller env, so a listed key there is
	// not refused: an older server that attaches one must not block the command.
	d := &cancelTestDispatcher{}
	wc, reports := cancelTestClient(t, d)

	wc.handleCommand(protocol.Command{
		ID:    "env-internal",
		Shell: "internal",
		Line:  "ping",
		User:  "root",
		Group: "root",
		Env:   map[string]string{"LD_PRELOAD": "/tmp/preload.so"},
	}, protocol.CommandData{})

	report := receiveCancelReport(t, reports)
	assert.Equal(t, int32(1), d.calls.Load())
	assert.NotEqual(t, commandEnvRefusedResult, report["result"])
}

func TestCommandRunner_Run_AdmittedEnvRunsAsBefore(t *testing.T) {
	env := map[string]string{benignEnvKey: "value", "LANG": "C.UTF-8", "HTTPS_PROXY": "http://proxy.example:3128"}
	command := protocol.Command{
		ID:    "env-admitted",
		Shell: "system",
		Line:  "echo hello",
		User:  "root",
		Group: "root",
		Env:   env,
	}

	d := &cancelTestDispatcher{}
	wc, reports := cancelTestClient(t, d)
	wc.handleCommand(command, protocol.CommandData{})

	report := receiveCancelReport(t, reports)
	assert.Equal(t, int32(1), d.calls.Load())
	assert.Equal(t, true, report["success"])
	assert.Equal(t, "unchanged", report["result"])

	// The handler receives the caller's env exactly as sent.
	command.ID = ""
	dispatcher := &fakeDispatcher{}
	require.NoError(t, NewCommandRunner(nil, nil, command, protocol.CommandData{}, dispatcher).Run(context.Background()))
	require.Len(t, dispatcher.calls, 1)
	assert.Equal(t, env, dispatcher.calls[0].args.Env)
}
