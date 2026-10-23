#!/bin/bash
# Read-only inventory; exit 1 means one or more checks were unavailable/incomplete.
set -uo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
if (($#)); then
  case $1 in --help|-h) printf 'Usage: sudo ./04-verify.sh\nRead-only, uncapped inventory. Output may contain secrets. Exit 1 = incomplete.\n'; exit 0 ;; *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;; esac
fi
STATUS=0
warn() { printf 'INCOMPLETE: %s\n' "$*" >&2; STATUS=1; }
sec() { printf '\n===== %s =====\n' "$*"; }
check() {
  local title=$1; shift; sec "$title"
  if ! command -v "$1" >/dev/null; then warn "$1 unavailable"; return; fi
  "$@" || warn "$title failed"
}
((EUID == 0)) || warn 'Run as root for protected data and process details'
check 'Logged-in users' who
check 'Recent logins (last 10)' last -n 10
check 'UID 0 accounts' awk -F: '$3==0 {print $1 ":" $3 ":" $6 ":" $7}' /etc/passwd
check 'Local users and shells' awk -F: '{print $1 " -> " $7}' /etc/passwd
sec 'Admin groups (both inspected; absence is normal)'
for group in wheel sudo; do getent group "$group" || printf 'Group %s absent or NSS lookup failed; review NSS if unexpected.\n' "$group"; done
check 'sudoers syntax and includes' visudo -c
sec 'sudoers standard paths (custom includes need manual follow-up)'
shopt -s nullglob
for file in /etc/sudoers /etc/sudoers.d/*; do
  [[ -f $file ]] || continue
  printf '\n%q\n' "$file"
  sed -n l -- "$file" || warn "cannot read $file"
done
check 'Enabled service units' systemctl list-unit-files --type=service --state=enabled --no-pager
check 'Running service units' systemctl list-units --type=service --state=running --no-pager
check 'Listening ports' ss -tlnup
# Mark backends not installed, without treating every optional backend as required.
found=0
for command in iptables-save ip6tables-save nft; do
  if command -v "$command" >/dev/null; then
    found=1
    if [[ $command == nft ]]; then check 'Full nftables ruleset' nft list ruleset
    else check "Full $command ruleset" "$command"; fi
  else printf 'Optional backend absent: %s\n' "$command"; fi
done
if command -v firewall-cmd >/dev/null; then
  if firewall-cmd --state; then
    found=1
    check 'All runtime firewalld zones' firewall-cmd --list-all-zones
    check 'All permanent firewalld zones' firewall-cmd --permanent --list-all-zones
  else printf 'Firewalld is installed but not running.\n'; fi
fi
((found)) || warn 'no firewall backend could be inspected'
if command -v docker >/dev/null; then check 'Docker containers and published ports' docker ps; else printf 'Docker CLI absent.\n'; fi
sec 'Cron schedules and spool'
for file in /etc/crontab /etc/anacrontab; do
  [[ ! -e $file ]] || { printf '\n%q\n' "$file"; sed -n l -- "$file" || warn "cannot read $file"; }
done
for dir in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
  [[ ! -d $dir ]] || { ls -la -- "$dir" || warn "cannot list $dir"; }
done
if command -v crontab >/dev/null; then
  while IFS=: read -r user rest; do
    printf '\nCrontab for %q (a no-crontab diagnostic is normal):\n' "$user"
    # Keep stderr visible so permission failures are distinguishable from absence.
    output=$(crontab -l -u "$user" 2>&1); code=$?
    printf '%s\n' "$output" | sed -n l
    if ((code != 0)) && [[ $output != *'no crontab for '* ]]; then warn "crontab check failed: $user"; fi
  done < /etc/passwd
else warn 'crontab unavailable'; fi
sec 'SSH authorization in account home directories'
while IFS=: read -r user unused uid gid gecos home shell; do
  [[ $home == /* && $home != / ]] || continue
  for file in "$home"/.ssh/authorized_keys "$home"/.ssh/authorized_keys2; do
    [[ -e $file || -L $file ]] || continue
    printf '\n%q\n' "$file"
    if [[ -L $file ]]; then readlink -- "$file" || warn "cannot read link: $file"; printf 'Review symlink target separately.\n'
    else sed -n l -- "$file" || warn "cannot read $file"; fi
  done
done < /etc/passwd
printf 'Custom SSH authorization paths, Match/Include and NSS-only users require follow-up.\n'
sec 'Files in /etc modified in the last 24 hours (all matches)'
find /etc -xdev -type f -mtime -1 -print0 | while IFS= read -r -d '' file; do printf '%q\n' "$file"; done
(( $? == 0 )) || warn 'recent-file traversal failed'
sec 'SUID binaries on root filesystem only (add other mounts separately)'
find / -xdev -perm -4000 -type f -print0 | while IFS= read -r -d '' file; do printf '%q\n' "$file"; done
(( $? == 0 )) || warn 'SUID traversal failed'
printf '\nInventory finished; status=%s (0 complete, 1 incomplete).\n' "$STATUS"
exit "$STATUS"
