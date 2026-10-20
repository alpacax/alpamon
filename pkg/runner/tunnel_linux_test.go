package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCodeServerCredentialRequiresGroup(t *testing.T) {
	attr, err := getCodeServerCredential("account", "")
	assert.EqualError(t, err, "groupname is required")
	assert.Nil(t, attr)
}
