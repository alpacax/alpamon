//go:build !windows

package utils

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessChildEnvironmentWithoutPasswdEntry(t *testing.T) {
	env, err := processChildEnvironment(strconv.Itoa(os.Geteuid()), func(string) (*user.User, error) { return nil, errors.New("unknown user") })
	require.NoError(t, err)
	assert.Contains(t, env, "HOME=/")
	for _, entry := range env {
		assert.False(t, strings.HasPrefix(entry, "USER=") || strings.HasPrefix(entry, "LOGNAME="))
	}
}
