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
// load, so a vector class added to the file needs a commandEnvVectors field.
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

func titleCase(key string) string {
	return strings.ToUpper(key[:1]) + strings.ToLower(key[1:])
}

func TestCommandEnvList_MatchesSharedVectors(t *testing.T) {
	vectors := loadCommandEnvVectors(t)

	assert.Equal(t, vectors.Prefixes, commandEnvPrefixes)
	assert.Equal(t, vectors.ExactNames, commandEnvExactNames)
}

func TestCommandEnvRefused_RefusesListedKeysInAnyCase(t *testing.T) {
	vectors := loadCommandEnvVectors(t)

	for _, key := range vectors.RefusedKeys {
		for _, variant := range []string{strings.ToUpper(key), strings.ToLower(key), titleCase(key)} {
			env := map[string]string{benignEnvKey: "value", variant: "value"}
			assert.Truef(t, commandEnvRefused(env), "key %q", variant)
		}
	}
}

func TestCommandEnvRefused_AdmitsUnlistedKeys(t *testing.T) {
	vectors := loadCommandEnvVectors(t)

	assert.False(t, commandEnvRefused(nil))
	for _, key := range vectors.AdmittedKeys {
		env := map[string]string{benignEnvKey: "value", key: "value"}
		assert.Falsef(t, commandEnvRefused(env), "key %q", key)
	}
}

func TestCommandEnvRefused_RefusesMalformedKeys(t *testing.T) {
	vectors := loadCommandEnvVectors(t)

	for _, key := range vectors.MalformedKeys {
		env := map[string]string{benignEnvKey: "value", key: "value"}
		assert.Truef(t, commandEnvRefused(env), "key %q", key)
	}
}

func TestCommandEnvRefused_RefusesFunctionValuesUnderAnyKey(t *testing.T) {
	vectors := loadCommandEnvVectors(t)

	for _, value := range vectors.RefusedValues {
		env := map[string]string{benignEnvKey: value}
		assert.Truef(t, commandEnvRefused(env), "value %q", value)
	}
}

func TestCommandEnvRefused_AdmitsOtherValues(t *testing.T) {
	vectors := loadCommandEnvVectors(t)

	for _, value := range vectors.AdmittedValues {
		env := map[string]string{benignEnvKey: value}
		assert.Falsef(t, commandEnvRefused(env), "value %q", value)
	}
}

func TestCommandRunner_Run_RefusedEnvFinishesBeforeAnyShellRuns(t *testing.T) {
	envs := map[string]map[string]string{
		"listed key":     {benignEnvKey: "value", "LD_PRELOAD": "/tmp/preload.so"},
		"malformed key":  {benignEnvKey: "value", "FOO-BAR": "value"},
		"function value": {benignEnvKey: "() { :; }"},
	}
	// "file" carries no payload, so it yields the env refusal only if the env
	// check comes first. "future" stands for a lane added later.
	for _, shell := range []string{"system", "file", "future"} {
		for name, env := range envs {
			t.Run(shell+"/"+name, func(t *testing.T) {
				d := &cancelTestDispatcher{}
				wc, reports := cancelTestClient(t, d)

				wc.handleCommand(protocol.Command{
					ID:    "env-refused-" + shell,
					Shell: shell,
					Line:  "ping",
					User:  "root",
					Group: "root",
					Env:   env,
				}, protocol.CommandData{})

				report := receiveCancelReport(t, reports)
				assert.Equal(t, int32(0), d.calls.Load(), "a refused env must never reach a handler")
				assert.Equal(t, false, report["success"])
				assert.Equal(t, float64(1), report["exit_code"])
				assert.Equal(t, commandEnvRefusedResult, report["result"])
			})
		}
	}
}

func TestCommandRunner_Run_InternalLaneNeitherRefusesNorAppliesEnv(t *testing.T) {
	// An older server that attaches a listed key must not block the command,
	// and the exemption holds only while this lane hands no env to a handler.
	command := protocol.Command{
		Shell: "internal",
		Line:  "ping",
		User:  "root",
		Group: "root",
		Env:   map[string]string{"LD_PRELOAD": "/tmp/preload.so"},
	}

	dispatcher := &fakeDispatcher{}
	require.NoError(t, NewCommandRunner(nil, nil, command, protocol.CommandData{}, dispatcher).Run(context.Background()))
	require.Len(t, dispatcher.calls, 1)
	assert.Equal(t, "ping", dispatcher.calls[0].command)
	assert.Empty(t, dispatcher.calls[0].args.Env)
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

	command.ID = ""
	dispatcher := &fakeDispatcher{}
	require.NoError(t, NewCommandRunner(nil, nil, command, protocol.CommandData{}, dispatcher).Run(context.Background()))
	require.Len(t, dispatcher.calls, 1)
	assert.Equal(t, map[string]string{
		benignEnvKey:  "value",
		"LANG":        "C.UTF-8",
		"HTTPS_PROXY": "http://proxy.example:3128",
	}, dispatcher.calls[0].args.Env)
}
