//go:build !linux

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The login_capture block is Linux-only: elsewhere it is omitted entirely,
// which the server reads as unknown rather than as uncovered.
func TestGetLoginCaptureOmittedOffLinux(t *testing.T) {
	assert.Nil(t, GetLoginCapture())
}
