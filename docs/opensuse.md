# openSUSE / SLES

Support is best-effort. Alpamon detects openSUSE and SLES, runs `zypper` for its own package operations, and starts cleanly, but the console still composes `yum` for some server-driven operations (see Known limitations below).

## Why the platform reads as rhel

openSUSE and SLES report `platform=rhel` to Alpacon. The three things the server gates on that value—rpm packaging, the `wheel` sudo group, and shadow-utils account tooling—behave identically on both families. The real distribution name is preserved separately in the OS information, and the agent runs `zypper` locally regardless of what it reports.

## Installation

The PackageCloud one-liner writes a yum repo file into `/etc/yum.repos.d/`, which zypper never reads, so add the repository to zypper directly:

```bash
sudo zypper addrepo -f \
  'https://packagecloud.io/alpacax/alpamon/rpm_any/rpm_any/$basearch' alpamon
sudo zypper --gpg-auto-import-keys refresh
sudo zypper install alpamon
sudo alpamon register --url https://<workspace> --token <TOKEN>
```

## Sudoers prerequisite

openSUSE ships `/etc/sudoers` with `Defaults targetpw` alongside `ALL ALL=(ALL) ALL`, so every user may already run any command—but only by typing root's password, not their own. Both `%wheel` lines in that file are commented out, so `wheel` membership grants nothing by itself. The drop-in below therefore does two things: it grants `%wheel` the rule, and it exempts `%wheel` from `targetpw` so Alpacon-managed admins authenticate as themselves.

Stage the drop-in under a name containing a dot, which sudo ignores when reading the include directory, so a typo cannot lock you out before `visudo -cf` has passed:

```bash
printf '%%wheel ALL=(ALL) ALL\nDefaults:%%wheel !targetpw\n' |
  sudo tee /etc/sudoers.d/alpacon-wheel.stage >/dev/null
sudo visudo -cf /etc/sudoers.d/alpacon-wheel.stage &&
  sudo install -m 0440 -o root -g root \
    /etc/sudoers.d/alpacon-wheel.stage /etc/sudoers.d/alpacon-wheel
sudo rm -f /etc/sudoers.d/alpacon-wheel.stage
```

## PAM module

```bash
sudo zypper install alpamon-pam
```

Configuration is the same as on other distributions; see the PAM section in the main README.

## Repository scope for agent upgrades

An unscoped `zypper refresh` fails with exit 4 if any single enabled repository is unreachable. On a long-lived host with a retired third-party repository or an expired subscription, chaining that refresh into the update would make `alpamon upgrade` and the console update button permanently unusable even though alpamon's own repository is fine.

The agent therefore resolves the alias of the enabled repository whose URL points at `packagecloud.io/alpacax/alpamon` and refreshes only that one, as its own command rather than chained. Any alias works; a disabled repository or no match at all falls back to refreshing everything. A refresh failure still stops the upgrade, because the refresh is what keeps a stale-metadata no-op from being reported as a successful upgrade.

The update itself is never scoped with `-r`. That option loads only the named repository, so dependency resolution then fails against the distribution repositories—`zypper install -r alpamon alpamon` reports `nothing provides 'nftables'`. Because the update stays unscoped, it exits 106 whenever any repository is unreachable; that code counts as success only when alpamon's own repository was refreshed on its own moments earlier, which rules out a skipped repository hiding a missed update.

System-wide updates cannot be scoped this way—by definition they cover every repository—so the console update button still fails while a repository is unreachable.

## Zypper exit codes

Unlike `apt-get` and `yum`, zypper reserves codes above 100 for informational states, and two of them follow a successful install. The agent maps those two to success and leaves everything else a failure, so a completed update does not surface in the console as a broken command:

| Code | Meaning | Reported as |
| --- | --- | --- |
| 102 | Reboot needed after a successful install | success |
| 103 | Package manager restart needed after a successful install | success |
| 100, 101 | Patches available, none installed | failure |
| 104 | No repository carries the requested package | failure |
| 106 | A repository was skipped because it failed to refresh | success for an agent upgrade whose own repository refreshed, failure otherwise |
| 107 | Installed, but an rpm `%post` script failed | failure |

100 and 101 come from `patch-check`, which the agent never runs, so they are anomalous here rather than informational. 104 means nothing was updated. 107 matters because `%post` is what registers the systemd units and the PAM session lines, so a package that unpacked with a failed script is not a working install.

## Known limitations

Because the host reports `rhel`, console-driven package operations that the server composes still emit `yum` commands and fail on a SUSE host: Alpacon plugin install/upgrade and the automatic `alpamon-pam` install. Install those manually with `zypper` until the server side is zypper-aware. The agent's own upgrade, uninstall, and system-update paths do use `zypper`.

The console's registration instruction is one of those commands. The registration form offers no SUSE option, and its RHEL guide renders `yum install -y alpamon`, which fails here. Follow the zypper commands under Installation above instead.

The `wheel` sudo group is granted but inert without the sudoers drop-in. For `rhel` the server adds Alpacon-managed admins to `wheel`, and that part succeeds on SUSE, but stock `/etc/sudoers` leaves both `%wheel` rules commented out, so membership alone authorizes nothing. Alpacon then shows the user as sudo-capable while the host refuses the command—the failure is silent, and nothing in the console reports it. The Sudoers prerequisite above is what closes the gap; skipping it leaves admins without sudo.

## Already-registered hosts

A host that registered before openSUSE/SLES detection landed carries a wrong `platform` value on the server. That field is write-once, so the host must re-register to pick up the correct value:

```bash
sudo alpamon register --force --url https://<workspace> --token <TOKEN>
```

This is not an in-place edit of the existing record. `--force` registers a new server, then retires the previous one, so the host gets a new ID. Tags are re-sent and survive; group memberships, console-side access rules, alert-rule customizations, and audit and session history stay attached to the retired record. For one host that is a minor annoyance—for an already-registered fleet, plan it as a migration rather than a routine re-register.
