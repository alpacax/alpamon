//go:build !darwin

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaxSupplementaryGroups_Uncapped(t *testing.T) {
	assert.Zero(t, maxSupplementaryGroups(), "only darwin caps the supplementary group list")
}
