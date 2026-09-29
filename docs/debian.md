# Debian / Ubuntu

## Repository scope for agent upgrades

`alpamon upgrade` refreshes only the alpamon source file: the `.list` or `.sources` file under `/etc/apt/sources.list.d` that carries the enabled packagecloud alpamon repository. It resolves that file by scanning every `.list` and `.sources` entry there for an active line naming `packagecloud.io/alpacax/alpamon/`—a commented-out `.list` line or a deb822 stanza with `Enabled: no` does not count, since apt itself skips them too.

The refresh scopes to that file with `Dir::Etc::sourcelist`, and `Dir::Etc::sourceparts=-` stops apt from also reading every other file in `sources.list.d`. `APT::Get::List-Cleanup=0` keeps apt from pruning the package lists that scoping just left unread, so a broken third-party repo elsewhere on the host does not lose its cached package list, and its outage cannot fail the refresh.

When no file resolves—no source directory, or none carrying an enabled alpamon repository—the refresh falls back to a full, unscoped `apt-get update`.

The install step that follows is unaffected by scoping: it upgrades `alpamon` (and `alpamon-pam`, when installed) against whatever the now current package lists resolve to.
