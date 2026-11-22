package archiveopen

import "golang.org/x/sys/unix"

// Openat2 can be substituted by archive tests to simulate older kernels.
var Openat2 = unix.Openat2
