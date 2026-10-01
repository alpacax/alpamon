# RHEL / Rocky / AlmaLinux / Fedora

## Repository availability for agent upgrades

yum and dnf load every enabled repository before they resolve anything, so one unreachable repository fails the whole command. `alpamon upgrade`, the pinned install, and the package rollback therefore pass a `--setopt=<id>.skip_if_unavailable=` option for each enabled repository: `True` for every repository except alpamon's, `False` for alpamon's own. A broken third-party repository such as `docker-ce-stable` is skipped with a warning, while an outage of alpamon's repository still fails the upgrade instead of ending in "Nothing to do." and a successful exit.

The agent finds alpamon's repositories by reading every `.repo` file in the directories dnf 4 and dnf 5 read by default: `/etc/yum.repos.d`, `/etc/yum/repos.d`, `/etc/distro.repos.d`, and `/usr/share/dnf5/repos.d`. A repository counts as alpamon's when its `baseurl`, `mirrorlist`, or `metalink` names one of the channel repositories `.github/workflows/release.yml` publishes to: `packagecloud.io/alpacax/alpamon/` (stable), `packagecloud.io/alpacax/alpamon-latest/` (rc), or `packagecloud.io/alpacax/alpamon-dev/` (dev, beta, alpha). A repository with `enabled=0` gets no option, since yum does not load it.

Every enabled channel repository stays strict, so an outage of any of them fails the upgrade: a host that moved from dev to stable but kept its `alpamon-dev` repository is blocked while that repository is down. Remove the repository of a channel the host no longer follows.

When no enabled alpamon repository resolves, the command runs without any of these options, exactly as before: skipping every repository would hide an outage of alpamon's own. A `reposdir=` override in `dnf.conf` is not read, so repositories in such a directory are treated the same way.
