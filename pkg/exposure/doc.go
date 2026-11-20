// Package exposure reports a Linux host's access-path metadata to the Alpacon
// server: local accounts and their password state, SSH authorized keys and
// user-CA trust, Kerberos and host-based trust files, sudo grants, the
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
// Before opening a source, fstatat(AT_SYMLINK_NOFOLLOW) checks its identity
// through the same pinned directory walk. Identity includes device, inode,
// size, nanosecond modification and change times, mode, owner uid and link
// count. The reader's ownership and path checks still apply. Directory
// sources also track the directory device, inode, nanosecond modification and
// change times, and the set of entry names. Adding, removing or renaming an
// entry causes a fresh read.
//
// A result is cached in memory for this process only, and only when its source
// read succeeded completely. Most sources are cached only without reasons. The
// sudo policy and account list are also cached with reasons, because those
// reasons depend only on tracked files and the host name.
// Unchanged sources are stat-ed but not opened; their facts, reasons and
// completeness are reused. File and directory timestamps must both be more
// than two seconds older than the stat time before results can be stored or
// reused, avoiding missed changes on filesystems with coarse clocks. Failed
// and partial reads are retried. The first collection reads every applicable
// source, and each fixed 24-hour deadline
// from collector start forces another full read on the next collection.
// Restarting always starts with full reads. This reduces endpoint-detection
// alert noise from repeated opens of unchanged sensitive files.
//
// # Allowlisting the reporter
//
// The installed process is /usr/bin/alpamon, running as root. It collects at
// start, hourly with up to five minutes of jitter, and on demand after sync
// triggers. On-demand collections use the same cache; a daily full read is
// due every 24 hours from start and runs with the next collection.
//
// Account sources are /etc/passwd, /etc/group, /etc/shadow, /etc/shells and
// /etc/nsswitch.conf. Sudo sources are /etc/sudo.conf, /etc/sudoers-rs,
// /etc/sudoers (or the configured sudoers_file), and included files and
// directories, commonly /etc/sudoers.d. SSH sources are /etc/ssh/sshd_config
// and its includes, the configured AuthorizedKeysFile,
// AuthorizedPrincipalsFile and TrustedUserCAKeys paths, /etc/krb5.conf,
// /etc/hosts.equiv, /etc/ssh/shosts.equiv, and each applicable account's
// .k5login, .rhosts and .shosts. Account homes, .ssh directories and all source
// parent directories are inspected as part of the descriptor walk. Each
// collection opens and lists the parent directory of every source, including
// /etc, /var/log, each applicable home and each .ssh directory, with
// O_RDONLY|O_DIRECTORY. Unchanged files are stat-ed but not opened.
//
// PTY sources are /var/log/wtmp, /var/log/wtmp.1 and /var/log/lastlog;
// /var/lib/wtmpdb/wtmp.db and /var/lib/lastlog/lastlog2.db are checked for
// existence only. When NSS uses systemd, directory entries are inspected in
// /var/lib/systemd/home, /etc/userdb, /run/userdb, /run/host/userdb,
// /usr/local/lib/userdb and /usr/lib/userdb. Daemon correspondence reads
// /proc/stat and /proc/<pid>/{stat,status,cmdline}. Each collection invokes
// /usr/sbin/sshd -T, or /usr/bin/sshd -T when that is the installed candidate,
// as root; this subprocess runs even when file results are reused.
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
