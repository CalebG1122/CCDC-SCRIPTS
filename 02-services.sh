#!/bin/bash
# Inventory and selectively disable services; package removals are interactive.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
usage() {
  cat <<'EOF'
Usage: 02-services.sh [--apply] [--disable UNIT ...] [--no-ssh --console] [--purge]
No units are disabled unless explicitly selected. --no-ssh additionally selects
sshd.service, ssh.service and ssh.socket and requires --console with no SSH session.
Each unit requires confirmation. --purge reviews installed legacy server packages
using the native package manager's interactive dependency/removal confirmation.
Do not select services scored by the competition. Inventory is read-only.
EOF
}
APPLY=0 NOSSH=0 CONSOLE=0 PURGE=0 STATUS=0 BACKUP=''
UNITS=()
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
while (($#)); do
  case $1 in
    --help|-h) usage; exit 0 ;;
    --apply) APPLY=1 ;;
    --no-ssh) NOSSH=1 ;;
    --console) CONSOLE=1 ;;
    --purge) PURGE=1 ;;
    --disable)
      (($# >= 2)) || die '--disable needs a unit'
      [[ $2 =~ ^[a-zA-Z0-9_@.:-]+\.(service|socket|timer)$ && $2 != -* ]] || die 'use an explicit service/socket/timer unit name'
      UNITS+=("$2"); shift ;;
    *) die "unknown option: $1" ;;
  esac; shift
done
(( ! APPLY || EUID == 0 )) || die '--apply requires root'
if ((NOSSH)); then
  ((CONSOLE)) && [[ -z ${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-} ]] || die '--no-ssh requires --console from a local console'
  UNITS+=(sshd.service ssh.service ssh.socket)
fi
if ((APPLY)) && { ((${#UNITS[@]})) || ((PURGE)); }; then
  [[ -t 0 && -t 1 ]] || die '--apply changes require an interactive terminal'
fi
command -v systemctl >/dev/null || die 'systemctl unavailable'
backup() {
  [[ -z $BACKUP ]] || return 0
  BACKUP=$(umask 077; mktemp -d /var/lib/ccdc-services.XXXXXXXX)
  systemctl list-unit-files --no-pager > "$BACKUP/unit-files.txt"
  systemctl list-units --all --no-pager > "$BACKUP/units.txt"
  printf 'Pre-change service inventory: %s\n' "$BACKUP"
}
for unit in "${UNITS[@]}"; do
  case $unit in ssh.service|sshd.service|ssh.socket|sshd.socket|sshd@*.service|ssh@*.service)
    ((CONSOLE)) && [[ -z ${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-} ]] || die 'SSH changes require --console from a local console' ;;
  esac
  load=$(systemctl show "$unit" -p LoadState --value) || { STATUS=1; continue; }
  if [[ $load == not-found ]]; then printf 'Absent: %s\n' "$unit"; continue; fi
  printf '\nProposed: disable and stop %s, then mask it.\n' "$unit"
  systemctl --no-pager cat "$unit" || { STATUS=1; continue; }
  ((APPLY)) || continue
  printf 'Type the full unit name to confirm: '; IFS= read -r answer || continue
  [[ $answer == "$unit" ]] || continue
  backup
  if ! systemctl disable --now "$unit"; then STATUS=1; continue; fi
  systemctl mask "$unit" || STATUS=1
done
if ((PURGE)); then
  packages=()
  if command -v dpkg-query >/dev/null && [[ -f /var/lib/dpkg/status ]]; then
    for p in telnetd inetutils-telnetd rsh-server tftpd tftpd-hpa vsftpd; do
      state=$(dpkg-query -W -f='${Status}' "$p" 2>/dev/null) || continue
      [[ $state != 'install ok installed' ]] || packages+=("$p")
    done
    manager=(apt-get purge --no-auto-remove)
  elif command -v rpm >/dev/null; then
    for p in telnet-server rsh-server vsftpd tftp-server; do
      if rpm -q "$p" >/dev/null 2>&1; then packages+=("$p"); fi
    done
    if command -v dnf >/dev/null; then manager=(dnf remove --setopt=clean_requirements_on_remove=False)
    elif command -v yum >/dev/null; then manager=(yum remove)
    else die 'no supported RPM package manager'; fi
  else die 'no supported package database'; fi
  if ((${#packages[@]})); then
    printf '\nInstalled package removal candidates: '; printf '%s ' "${packages[@]}"; printf '\n'
    if ((APPLY)); then
      backup
      printf '%s\n' "${packages[@]}" > "$BACKUP/package-candidates.txt"
      printf 'Review ALL dependent removals in the package manager prompt.\n'
      "${manager[@]}" "${packages[@]}" || STATUS=1
    fi
  else printf 'No matching installed packages.\n'; fi
fi
systemctl list-unit-files --type=service --state=enabled --no-pager || STATUS=1
systemctl list-units --type=service --state=running --no-pager || STATUS=1
if command -v ss >/dev/null; then ss -tlnup || STATUS=1; else printf 'INCOMPLETE: ss unavailable\n' >&2; STATUS=1; fi
((APPLY)) || printf 'Dry run; no changes made.\n'
exit "$STATUS"
