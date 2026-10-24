# CCDC administrative scripts

Linux and Bash 4+ required. Review the competition's scored services and account
requirements before applying a change. Scripts default to inventory/planning;
help works without root. They never evaluate discovered configuration commands.
Default output is a brief summary. Add --verbose to accounts, services, firewall
or verification for the detailed listings. All verification checks still run in
summary mode; their failure diagnostics and exit status remain visible. Explicit
changes still show their proposals and confirmations.

```bash
python3 tests/test_scripts.py
sudo ./01-users.sh
sudo ./01-users.sh --restrict-admins --keep-admin youradmin --apply
sudo ./01-users.sh --restrict-logins --keep-login youradmin --keep-login scoreduser --apply
sudo ./01-users.sh --password root --apply
sudo ./02-services.sh
sudo ./02-services.sh --disable telnet.socket --apply
sudo ./02-services.sh --purge --apply
sudo ./04-verify.sh
```

Account restrictions require explicit keep lists. Root and SUDO_USER are always
protected. Both sudo and wheel supplementary memberships are reviewed, but primary
admin group membership, sudoers rules, and NSS/directory accounts require manual
follow-up. nologin does not terminate sessions, revoke keys or prevent all SSH
forwarding. Account backups contain sensitive password hashes; keep them private.
Do not blindly restore account databases after intervening account changes.

Service changes require named units and per-item confirmation. SSH changes require
an asserted local console and are rejected when SSH session environment variables
are present. Stopping another dependency can also affect remote access; review unit
relationships before confirming. Before mutation, service enabled/running states
are recorded privately in /var/lib. Packages use distribution-specific installed
names and the native manager's interactive dependency/removal review. Abort if any
scored application or dependency is listed. Backups do not reinstall packages or
automatically restart services; recovery needs an operator's review.

## Firewall

```bash
# Example documentation networks: replace with actual competition networks.
./03-firewall.sh --management-source 192.0.2.0/24 --scoring-source 198.51.100.10/32
sudo ./03-firewall.sh --management-source 192.0.2.0/24 --scoring-source 198.51.100.10/32 --apply
```

Management sources also default to web/forwarder access; override with repeatable
--web-source and --forwarder-source. Use IPv6 CIDRs too if new IPv6 service
connections are needed. Scoring sources reach all selected service ports. Use
--ssh-port for a nonstandard SSH port. --no-scoring is an explicit acknowledgement
for environments without a scoring engine. --no-ssh requires --console locally.

Apply requires iptables AND ip6tables (matching save/restore backends), Python 3,
systemd, GNU timeout and flock. Active firewalld/UFW are refused before changes;
this intentionally replaces the unsafe former firewalld apply path. Configure
those managers natively rather than disabling them to run this script. Native nft
rules outside the iptables compatibility tables are not modified or snapshotted
and may further restrict allowed traffic. Docker backends without the required
DOCKER-USER hooks are unsupported and refused when detected.

Both original rulesets are saved privately, tested for restorability, then an
independent systemd timer is armed before mutation. Apply has a hard time limit.
The timer restores both families after 90 seconds even if the foreground SSH shell
dies. Test a NEW SSH connection, web, ingestion and scoring before typing keep
within 60 seconds. A state lock prevents the commit decision racing with rollback.
On failed restoration the service retries; inspect its journal and saved state.
This protects against shell termination, not failure of systemd, the kernel, disk,
or the host itself. Keep console access available during live validation.

The managed INPUT chain denies other new inbound traffic; loopback, existing
connections and ICMP remain allowed. Existing connections from excluded sources
are not forcibly terminated. Docker rules filter ORIGINAL destination ports
8000/9997/8088/8089 before existing DOCKER-USER allowances; permitted traffic then
returns to Docker's existing rules. Other forwarded ports are unchanged. Loopback
host access to 8089 is retained; external INPUT/covered Docker access is denied.
Other container runtimes and rootless/userland proxies require separate review.
No reboot persistence is changed. Do not concurrently alter firewall/Docker state
during the snapshot/apply/confirmation window, as rollback restores the snapshot.

The backup directory printed by the script contains ipv4.rules, ipv6.rules,
apply.sh, rollback.sh and state. For manual restoration after a committed change,
inspect the backups, set state to pending under the state.lock with flock, and run
the saved rollback.sh as root. Successful snapshots are retained for investigation.

## Downloading and verification

```bash
# Obtain a reviewed commit SHA from GitHub; moving branch/tag names are rejected.
./get.sh --ref FULL_40_CHARACTER_COMMIT_SHA
```

get.sh creates a private directory, fetches all four operational scripts at that
exact commit, and syntax-checks all before granting executable permissions. It
does not overwrite or execute existing local files. Failed staging directories
retain an INCOMPLETE marker. Only --baseline runs the downloaded verifier, after
interactive confirmation as root; output is private baseline.txt. Review downloaded
code first. The hunter in PR #1 is intentionally independent of this fix PR.

04-verify.sh has a short default summary, uncapped firewall output with --verbose,
visible diagnostics, and status 1 for
incomplete checks. Optional absent backends are labeled. A root-filesystem SUID
search does not cover other mounts. Output may contain credentials or key comments;
save it privately (for example, umask 077 before redirecting). Reads may update
access times and audit logs as configured by the OS.

## Validation

Regression tests never change real accounts, services or firewalls. They cover
Bash syntax/help/argument validation, address-family separation in rule plans,
staged download failure/success, and extracted rollback code using fake restore
commands for both families, committed state and failed restoration. GitHub Actions
runs these on Linux. Actual systemd watchdog scheduling, firewall kernel behavior,
Docker forwarding, account changes and package operations still require testing
on a disposable Linux VM with console access before production use.
