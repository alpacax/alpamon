# Debian / Ubuntu

## Repository scope for agent upgrades

`alpamon upgrade` refreshes only the alpamon source files: each `.list` or `.sources` file under `/etc/apt/sources.list.d` that carries an enabled packagecloud alpamon repository. It resolves those files by scanning every `.list` and `.sources` entry there for an active line naming one of the channel repositories `.github/workflows/release.yml` publishes to: `packagecloud.io/alpacax/alpamon/` (stable), `packagecloud.io/alpacax/alpamon-latest/` (rc), or `packagecloud.io/alpacax/alpamon-dev/` (dev, beta, alpha). A commented-out `.list` line or a deb822 stanza with `Enabled: no` does not count, since apt itself skips them too.

A host that carries more than one channel refreshes all of them, one `apt-get update` per file, so a release promoted to stable is seen by a host running an rc build and the next rc is seen too.

Each refresh scopes to its file with `Dir::Etc::sourcelist`, and `Dir::Etc::sourceparts=-` stops apt from also reading every other file in `sources.list.d`. `APT::Get::List-Cleanup=0` keeps apt from pruning the package lists that scoping just left unread, so a broken third-party repo elsewhere on the host does not lose its cached package list, and its outage cannot fail the refresh.

When no file resolves—no source directory, or none carrying an enabled alpamon repository—the refresh falls back to a full, unscoped `apt-get update`.

The install step that follows is unaffected by scoping: it upgrades `alpamon` (and `alpamon-pam`, when installed) against whatever the now current package lists resolve to.
