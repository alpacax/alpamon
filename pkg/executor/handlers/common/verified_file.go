package common

// VerifiedFileChildFD is the descriptor number a digest-verified entrypoint
// lands on in the child process. os/exec maps ExtraFiles[i] to fd 3+i and the
// file execution path passes exactly one file, so it is always 3.
const VerifiedFileChildFD = 3
