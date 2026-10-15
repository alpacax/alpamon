package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoveSocket_MissingPathIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.sock")

	err := RemoveSocket(path)

	assert.NoError(t, err)
}

func TestRemoveSocket_RefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.sock")
	require.NoError(t, os.WriteFile(path, []byte("keep"), 0600))

	err := RemoveSocket(path)

	assert.ErrorContains(t, err, "non-socket")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(content))
}
