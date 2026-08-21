package protocol

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestParseFileExecPayload_Valid(t *testing.T) {
	cmd := &Command{
		Shell: "file",
		Line:  "/bin/bash /opt/deploy.sh --fast",
		Data:  `{"path":"/opt/deploy.sh","interpreter":"/bin/bash","args":["--fast"],"sha256":"` + testDigest + `"}`,
	}

	payload, err := cmd.ParseFileExecPayload()
	require.NoError(t, err)
	assert.Equal(t, "/opt/deploy.sh", payload.Path)
	assert.Equal(t, "/bin/bash", payload.Interpreter)
	assert.Equal(t, []string{"--fast"}, payload.Args)
	assert.Equal(t, strings.TrimPrefix(testDigest, "sha256:"), payload.ExpectedDigest())
}

func TestParseFileExecPayload_NoArgsIsValid(t *testing.T) {
	cmd := &Command{
		Shell: "file",
		Data:  `{"path":"/opt/deploy.sh","interpreter":"/bin/bash","sha256":"` + testDigest + `"}`,
	}

	payload, err := cmd.ParseFileExecPayload()
	require.NoError(t, err)
	assert.Empty(t, payload.Args)
}

func TestParseFileExecPayload_UpperCaseDigestIsNormalized(t *testing.T) {
	cmd := &Command{
		Shell: "file",
		Data:  `{"path":"/opt/deploy.sh","interpreter":"/bin/bash","sha256":"` + strings.ToUpper(testDigest) + `"}`,
	}

	payload, err := cmd.ParseFileExecPayload()
	require.NoError(t, err)
	assert.Equal(t, strings.TrimPrefix(testDigest, "sha256:"), payload.ExpectedDigest())
}

func TestParseFileExecPayload_UnknownFieldsAreIgnored(t *testing.T) {
	// Forward compatibility: a newer server adding a field must not turn every
	// file command into a refusal on an older agent.
	cmd := &Command{
		Shell: "file",
		Data:  `{"path":"/opt/deploy.sh","interpreter":"/bin/bash","sha256":"` + testDigest + `","future":"value"}`,
	}

	_, err := cmd.ParseFileExecPayload()
	assert.NoError(t, err)
}

// Malformed payloads must fail closed with an error naming what is wrong,
// never a panic and never a usable payload.
func TestParseFileExecPayload_Malformed(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{
			name:    "empty data",
			data:    "",
			wantErr: "no data payload",
		},
		{
			name:    "blank data",
			data:    "   ",
			wantErr: "no data payload",
		},
		{
			name:    "not json",
			data:    "/bin/bash /opt/deploy.sh",
			wantErr: "not valid JSON",
		},
		{
			name:    "truncated json",
			data:    `{"path":"/opt/deploy.sh"`,
			wantErr: "not valid JSON",
		},
		{
			name:    "json array",
			data:    `["/bin/bash","/opt/deploy.sh"]`,
			wantErr: "not valid JSON",
		},
		{
			name:    "wrong type for args",
			data:    `{"path":"/opt/deploy.sh","interpreter":"/bin/bash","args":"--fast","sha256":"` + testDigest + `"}`,
			wantErr: "not valid JSON",
		},
		{
			name:    "missing path",
			data:    `{"interpreter":"/bin/bash","sha256":"` + testDigest + `"}`,
			wantErr: "no path",
		},
		{
			name:    "missing interpreter",
			data:    `{"path":"/opt/deploy.sh","sha256":"` + testDigest + `"}`,
			wantErr: "no interpreter",
		},
		{
			name:    "missing digest",
			data:    `{"path":"/opt/deploy.sh","interpreter":"/bin/bash"}`,
			wantErr: "no valid sha256 digest",
		},
		{
			name:    "digest without algorithm prefix",
			data:    `{"path":"/opt/deploy.sh","interpreter":"/bin/bash","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`,
			wantErr: "no valid sha256 digest",
		},
		{
			name:    "digest too short",
			data:    `{"path":"/opt/deploy.sh","interpreter":"/bin/bash","sha256":"sha256:abcd"}`,
			wantErr: "no valid sha256 digest",
		},
		{
			name:    "digest not hex",
			data:    `{"path":"/opt/deploy.sh","interpreter":"/bin/bash","sha256":"sha256:zzz0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`,
			wantErr: "no valid sha256 digest",
		},
		{
			name:    "wrong algorithm",
			data:    `{"path":"/opt/deploy.sh","interpreter":"/bin/bash","sha256":"md5:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`,
			wantErr: "no valid sha256 digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &Command{Shell: "file", Data: tt.data}

			payload, err := cmd.ParseFileExecPayload()

			require.Error(t, err)
			assert.Nil(t, payload)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestParseFileExecPayload_RelativeInterpreterRefused(t *testing.T) {
	// A bare name resolves through PATH at exec time, and PATH comes from the
	// command's own environment. The digest binds the script, never the program
	// interpreting it, so this would swap what actually runs while the approved
	// digest still matched.
	cmd := &Command{Data: `{
		"path": "/opt/deploy.sh",
		"interpreter": "bash",
		"args": [],
		"sha256": "sha256:` + strings.Repeat("a", 64) + `"
	}`}

	_, err := cmd.ParseFileExecPayload()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "interpreter is not absolute")
}

func TestParseFileExecPayload_RelativePathRefused(t *testing.T) {
	cmd := &Command{Data: `{
		"path": "deploy.sh",
		"interpreter": "/bin/bash",
		"args": [],
		"sha256": "sha256:` + strings.Repeat("a", 64) + `"
	}`}

	_, err := cmd.ParseFileExecPayload()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "path is not absolute")
}
