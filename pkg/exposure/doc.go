// Package exposure reports a Linux host's access-path metadata to the Alpacon
// server: local accounts and their password state, SSH authorized keys and
// user-caKey trust, Kerberos and host-based trust files, sudo grants, the
// effective sshd policy and each account's last PTY login.
//
// # What leaves the host
//
// The report is built from typed structs whose fields hold only allowlisted
// metadata. Password hashes, private keys, public-key blobs (only the OpenSSH
// SHA-256 fingerprint is derived), certificate bodies, option values outside
// the allowlist, raw lastlog or wtmp records, raw configuration or sudoers
// lines and raw subprocess output never reach a field, a log line or the
// hash input. Malformed input becomes a reason code and a count.
//
// # How files are read
//
// Every path is walked one component at a time from a pinned directory
// descriptor with openat2(RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS), or with
// O_NOFOLLOW where the kernel lacks openat2, and the file is validated with
// fstat on the descriptor it is read from. A symlink anywhere on the path, a
// non-regular file, a foreign owner or a second hard link makes the source
// "rejected". Reads stop at 1 MiB plus one byte, lines at 16 KiB, and a file
// whose size or modification time moves during the read is discarded as a
// concurrent change.
//
// # Programs it runs
//
// The only subprocess is "sshd -T", from a fixed absolute path, without a
// shell, with a 5-second deadline and a capped stdout. Nothing here runs
// sudo, visudo, cvtsudoers or sudo-rs, or calls into PAM.
//
// # Platforms
//
// The collector and its transport build only on Linux. Other builds compile
// Start and Trigger as no-ops and never call the two endpoints.
package exposure
