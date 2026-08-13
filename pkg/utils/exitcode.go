package utils

// ConfigErrorExitCode is the exit status for a startup failure no restart can
// clear (sysexits.h EX_CONFIG). configs/alpamon.service repeats the literal in
// RestartPreventExitStatus, so the unit settles in failed with the reason still
// readable instead of relaunching into the same failure.
const ConfigErrorExitCode = 78
