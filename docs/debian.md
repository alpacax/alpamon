# Debian / Ubuntu

## Repository scope for agent upgrades

`alpamon upgrade` refreshes only the alpamon source files: each `.list` or `.sources` file under `/etc/apt/sources.list.d` that carries an enabled packagecloud alpamon repository. It resolves those files by scanning every `.list` and `.sources` entry there for an active line naming one of the channel repositories `.github/workflows/release.yml` publishes to: `packagecloud.io/alpacax/alpamon/` (stable), `packagecloud.io/alpacax/alpamon-latest/` (rc), or `packagecloud.io/alpacax/alpamon-dev/` (dev, beta, alpha). A commented-out `.list` line or a deb822 stanza with `Enabled: no` does not count, since apt itself skips them too.

A host that carries more than one channel refreshes all of them, one `apt-get update` per file, so a release promoted to stable is seen by a host running an rc build and the next rc is seen too. The cost is that an outage of any enabled channel repository fails the upgrade: a host that moved from dev to stable but kept its `alpamon-dev` source is blocked while that repository is down. A leftover source also lets the install pick that channel's build when it is newer, so remove the source of a channel the host no longer follows.

Each refresh scopes to its file with `Dir::Etc::sourcelist`, and `Dir::Etc::sourceparts=-` stops apt from also reading every other file in `sources.list.d`. `APT::Get::List-Cleanup=0` keeps apt from pruning the package lists that scoping just left unread, so a broken third-party repo elsewhere on the host does not lose its cached package list, and its outage cannot fail the refresh.

When no file resolves—no source directory, or none carrying an enabled alpamon repository—the refresh falls back to a full, unscoped `apt-get update`.

The install step that follows is unaffected by scoping: it upgrades `alpamon` (and `alpamon-pam`, when installed) against whatever the now current package lists resolve to.

## Waiting for the dpkg lock

Every apt command that installs or removes a package—the upgrade, the pinned upgrade and its rollback, the system update, and the uninstall—passes `-o DPkg::Lock::Timeout=300`. A held dpkg lock then makes apt wait up to five minutes instead of exiting 100 at once. The usual holder is `unattended-upgrades`, which `apt-daily-upgrade.timer` starts daily between 06:00 and 07:00.

The option covers only `/var/lib/dpkg/lock-frontend` and `/var/lib/dpkg/lock`, and only on apt 1.9.11 and later. Two cases still fail at once with exit code 100:

- apt before 1.9.11 (Ubuntu 18.04 ships 1.6, Debian 10 ships 1.8) tries each lock once and gives up. 1.9.11 is the release that made apt wait for the dpkg locks and read `DPkg::Lock::Timeout`; older apt accepts the option without error and never reads it, so a held dpkg lock fails the command as it did before the option was passed. Measured on apt 1.6.17 and 1.8.2.3.
- No apt version waits for `/var/lib/apt/lists/lock`, which `apt-get update` takes, or for `/var/cache/apt/archives/lock`, which the download takes. An upgrade that overlaps `apt-daily.service` refreshing the package lists fails at its `apt-get update` step.

The agent does not retry these. apt-get exits 100 on every error, so only its output tells a held lock apart, and matching that text is not reliable: apt 1.x translates it under a non-English locale, and its wording differs between apt versions. Run the command again once the other apt process finishes.
