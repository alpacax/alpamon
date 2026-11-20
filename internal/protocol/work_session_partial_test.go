package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkSessionRejectsAttributionWithoutID(t *testing.T) {
	partials := map[string]struct {
		revision Uint64String
		expiry   string
	}{
		"revision": {revision: 3},
		"expiry":   {expiry: "2026-11-18T10:00:00Z"},
	}
	for field, partial := range partials {
		t.Run(field, func(t *testing.T) {
			cases := map[string]struct {
				command Command
				data    *CommandData
			}{
				"command with nil data": {
					command: Command{WorkSessionRevision: partial.revision, WorkSessionExpiresAt: partial.expiry},
				},
				"command with empty data": {
					command: Command{WorkSessionRevision: partial.revision, WorkSessionExpiresAt: partial.expiry},
					data:    &CommandData{},
				},
				"data with empty command": {
					data: &CommandData{WorkSessionRevision: partial.revision, WorkSessionExpiresAt: partial.expiry},
				},
				"command with attributed data": {
					command: Command{WorkSessionRevision: partial.revision, WorkSessionExpiresAt: partial.expiry},
					data:    &CommandData{WorkSessionID: testWorkSessionID, WorkSessionRevision: 3},
				},
				"data with attributed command": {
					command: Command{WorkSessionID: testWorkSessionID, WorkSessionRevision: 3},
					data:    &CommandData{WorkSessionRevision: partial.revision, WorkSessionExpiresAt: partial.expiry},
				},
			}
			for name, tc := range cases {
				t.Run(name, func(t *testing.T) {
					ws, err := tc.command.WorkSession(tc.data)
					assert.ErrorContains(t, err, "work session ID")
					assert.Equal(t, WorkSession{}, ws)
				})
			}
		})
	}
}

func TestWorkSessionAllowsAbsentAttribution(t *testing.T) {
	for name, data := range map[string]*CommandData{"nil data": nil, "empty data": {}} {
		t.Run(name, func(t *testing.T) {
			ws, err := (&Command{}).WorkSession(data)
			require.NoError(t, err)
			assert.Equal(t, WorkSession{}, ws)
		})
	}
}
