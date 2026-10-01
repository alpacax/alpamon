# RHEL / Rocky / AlmaLinux / Fedora

## Repository availability for agent upgrades

yum and dnf load every enabled repository before they resolve anything, so one unreachable repository fails the whole command. `alpamon upgrade`, the pinned install, and the package rollback therefore pass `--setopt=*.skip_if_unavailable=True`, followed by `--setopt=<id>.skip_if_unavailable=False` for each of alpamon's own repositories; the option naming one id wins over the glob. A broken third-party repository such as `docker-ce-stable` is skipped with a warning, while an outage of alpamon's repository still fails the upgrade instead of ending in "Nothing to do." and a successful exit. No third-party repository is named, because dnf5 exits 2 on a `--setopt` for a repository id it has not loaded.

The agent finds alpamon's repositories by reading every `.repo` file in `/etc/yum.repos.d`, `/etc/yum/repos.d`, `/etc/distro.repos.d`, and `/usr/share/dnf5/repos.d`: the union of the directories dnf 4 and dnf5 read by default. A repository counts as alpamon's when its `baseurl`, `mirrorlist`, or `metalink` names one of the channel repositories `.github/workflows/release.yml` publishes to: `packagecloud.io/alpacax/alpamon/` (stable), `packagecloud.io/alpacax/alpamon-latest/` (rc), or `packagecloud.io/alpacax/alpamon-dev/` (dev, beta, alpha). A repository with `enabled=0` is not counted.

Every enabled channel repository stays strict, so an outage of any of them fails the upgrade: a host that moved from dev to stable but kept its `alpamon-dev` repository is blocked while that repository is down. Remove the repository of a channel the host no longer follows.

When no enabled alpamon repository resolves, the command runs without any of these options, exactly as before: skipping every repository would hide an outage of alpamon's own. A `reposdir=` override in `dnf.conf` is not read, so an alpamon repository that lives only in such a directory is not found and the command runs without options. On dnf5, an alpamon repository in a directory dnf5 does not load, such as `/etc/yum/repos.d`, makes the command exit 2 rather than report that there is nothing to upgrade.

On yum 3 (CentOS 7), `skip_if_unavailable` covers a repository whose `baseurl` fails but not one whose `mirrorlist` fails: yum still stops at `Cannot find a valid baseurl for repo`. Disable such a repository, or point it at a working mirror, before upgrading.
