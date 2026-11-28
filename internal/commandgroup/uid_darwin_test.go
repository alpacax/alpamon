package commandgroup

import (
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestRealUID(t *testing.T) {
	assert.Equal(t, strconv.Itoa(os.Getuid()), RealUID(os.Getpid()))
	info := unix.KinfoProc{}
	info.Eproc.Pcred.P_ruid = 501
	info.Eproc.Ucred.Uid = 0
	assert.Equal(t, "501", realUID(&info))
	info.Eproc.Pcred.P_ruid = 0
	assert.Equal(t, "0", realUID(&info))
}
