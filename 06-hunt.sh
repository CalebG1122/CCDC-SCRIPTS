#!/bin/bash
# Linux persistence inventory. Bash 4+, GNU coreutils/findutils expected.
# No commands found in inspected configuration are evaluated or executed.
set -u
set -o pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset BASH_ENV ENV CDPATH
shopt -s nullglob dotglob
CLEAN=0 SINCE='6 hours ago' LIMIT=300
declare -a ROOTS=() CANDIDATES=() DIGESTS=()
declare -A SEEN=()
usage() {
  cat <<'EOF'
Usage: sudo bash 06-hunt.sh [--since DATE] [--root DIR ...] [--limit N] [--clean]
       bash 06-hunt.sh --help

Default: read-only inventory; creates no temporary files or backups.
  --since DATE  GNU date expression for recent mtime/ctime (default: 6 hours ago)
  --root DIR    Recent/hidden-file search root; repeatable. Default: /etc /var/spool
                /usr/local /opt /tmp /var/tmp /root /home. Does not cross mounts.
  --limit N     Maximum recent/hidden paths printed per root (default: 300).
                The entire tree is still traversed. Permission errors are visible.
  --clean       Offer per-file quarantine of unowned regular cron files ONLY.
                Requires root and a controlling terminal. Default answer is no.

Ownership, hidden names and timestamps are context, never proof of compromise.
No automatic edits to sudoers, SSH keys, accounts, crontabs, at jobs, systemd,
or recent/hidden files. No services are stopped and no inspected code is run.
Cleanup first makes a private verified backup, then moves the original to that
backup directory. It does not delete it. Review impact before confirming.
Run cleanup only on a quiescent trusted host: shell checks cannot eliminate races
with concurrent privileged changes. A compromised kernel/toolchain can lie.
Output may contain private keys' comments, job environments and other secrets.
Reads can update access times and system audit logs under normal OS policy.
Exit: 0 completed (findings are informational); 1 incomplete checks; 2 usage error.
EOF
}
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
while (($#)); do
  case $1 in
    --help|-h) usage; exit 0 ;;
    --clean) CLEAN=1 ;;
    --since|--root|--limit)
      (($# >= 2)) || die "$1 requires a value"
      case $1 in
        --since) SINCE=$2 ;;
        --root) [[ $2 == /* && -d $2 ]] || die 'root must be an existing absolute directory'; ROOTS+=("$2") ;;
        --limit) [[ $2 =~ ^[1-9][0-9]{0,5}$ ]] || die 'limit must be 1..999999'; LIMIT=$2 ;;
      esac; shift ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done
((BASH_VERSINFO[0] >= 4)) || die 'Bash 4+ required'
SINCE_EPOCH=$(date -d "$SINCE" +%s 2>/dev/null) || die 'invalid --since date'
[[ $SINCE_EPOCH =~ ^-?[0-9]+$ ]] || die 'date did not produce an epoch'
STATUS=0
warn() { printf 'INCOMPLETE: %s\n' "$*" >&2; STATUS=1; }
for tool in date find stat head sed awk sha256sum readlink; do
  command -v "$tool" >/dev/null || die "required command unavailable: $tool"
done
section() { printf '\n== %s ==\n' "$*"; }
# Escape terminal controls and cap file output. Never cat arbitrary files.
show() {
  [[ -f $1 && -r $1 ]] || { warn "unreadable/non-regular file: $1"; return; }
  head -c 65536 -- "$1" | sed -n '1,200l'
  printf '(display capped at 64 KiB / 200 lines)\n'
}
PKG=none
if command -v rpm >/dev/null && [[ -d /var/lib/rpm || -d /usr/lib/sysimage/rpm ]]; then PKG=rpm
elif command -v dpkg-query >/dev/null && [[ -f /var/lib/dpkg/status ]]; then PKG=dpkg
fi
owner() {
  case $PKG in
    rpm) rpm -qf -- "$1" 2>/dev/null ;;
    dpkg) dpkg-query -S -- "$1" 2>/dev/null ;;
    *) return 2 ;;
  esac
}
fingerprint() { stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "$1" && sha256sum -- "$1"; }
inspect() {
  local f=$1 kind=${2:-config} owned
  [[ -n ${SEEN["$f"]+yes} ]] && return
  SEEN["$f"]=1
  printf '\n[%s] %q\n' "$kind" "$f"
  if [[ -L $f ]]; then
    printf 'Symlink target: '; readlink -- "$f" | sed -n l
    printf 'Symlink contents not followed; review target separately.\n'; return
  fi
  [[ -f $f ]] || return
  stat -c 'mode=%a owner=%u:%g links=%h size=%s modified=%y' -- "$f" || warn "stat failed: $f"
  if owned=$(owner "$f"); then printf 'Package: %s\n' "$owned" | sed -n l
  else
    printf 'REVIEW: package ownership absent or unavailable; local files can be legitimate.\n'
    if [[ $kind == cron && $PKG != none && -r $f && ! -L $f ]]; then
      CANDIDATES+=("$f"); DIGESTS+=("$(fingerprint "$f")")
    fi
  fi
  show "$f"
}
((EUID == 0)) || warn 'non-root run: other users and protected files may be missing'
if ((CLEAN)); then
  ((EUID == 0)) || die '--clean requires root'
  [[ -r /dev/tty && -w /dev/tty ]] || die '--clean requires a controlling terminal'
  for tool in realpath sha256sum stat cp mv mktemp cmp; do command -v "$tool" >/dev/null || die "cleanup requires $tool"; done
fi
printf 'Read-only scan; package database=%s; since=%s\n' "$PKG" "$SINCE"
section 'System cron: inspect schedules and execution commands'
inspect /etc/crontab
[[ ! -e /etc/anacrontab ]] || inspect /etc/anacrontab
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  for f in "$d"/*; do inspect "$f" cron; done
done
section 'Per-user cron spool (including orphaned crontabs; no edits)'
for d in /var/spool/cron /var/spool/cron/crontabs /var/spool/cron/tabs; do
  for f in "$d"/*; do [[ -d $f ]] || inspect "$f"; done
done
section 'at jobs: queued commands and environments (sensitive)'
if command -v atq >/dev/null && command -v at >/dev/null; then
  queue=$(atq) || { warn 'at queue unavailable'; queue=''; }
  printf '%s\n' "$queue" | sed -n l
  while read -r job rest; do
    [[ $job =~ ^[0-9]+$ ]] || continue
    printf '\nJob %s\n' "$job"
    at -c "$job" | head -c 65536 | sed -n '1,200l'
  done <<< "$queue"
else warn 'at/atq unavailable; checking known spool paths only'
fi
for d in /var/spool/at /var/spool/atjobs /var/spool/cron/atjobs; do
  for f in "$d"/*; do [[ -d $f ]] || inspect "$f"; done
done
section 'Systemd manager inventory and effective commands'
if command -v systemctl >/dev/null; then
  systemctl --no-pager list-unit-files --type=service,timer,socket || warn 'systemd unit-file listing unavailable'
  systemctl --no-pager list-timers --all || warn 'timer state unavailable'
  systemctl --no-pager list-sockets --all || warn 'socket state unavailable'
  while read -r unit rest; do
    [[ $unit == *.service || $unit == *.timer || $unit == *.socket ]] || continue
    systemctl --no-pager show "$unit" -p Id -p FragmentPath -p DropInPaths -p User -p ExecStart -p ExecStartPre -p ExecStartPost -p ExecStop -p EnvironmentFiles -p Triggers -p UnitFileState | sed -n l || warn "cannot inspect unit: $unit"
  done < <(systemctl --no-legend --no-pager list-unit-files --type=service,timer,socket)
else warn 'systemctl unavailable; disk configuration inspected below'
fi
scan_units() {
  local d=$1 f
  [[ -d $d ]] || return
  # Include all unit types, enablement links, drop-ins and generators.
  while IFS= read -r -d '' f; do
    if [[ $f == SCAN_FAILED ]]; then warn "unit traversal failed: $d"; else inspect "$f" systemd; fi
  done < <(find "$d" -xdev \( -type f -o -type l \) -print0 || printf 'SCAN_FAILED\0')
}
section 'System and global user units/drop-ins, generators and enablement'
for d in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/systemd/user /run/systemd/user /usr/local/lib/systemd/user /usr/lib/systemd/user /etc/systemd/system-generators /run/systemd/system-generators /usr/lib/systemd/system-generators /etc/systemd/user-generators /usr/lib/systemd/user-generators /run/systemd/generator /run/systemd/generator.early /run/systemd/generator.late; do scan_units "$d"; done
section 'sudoers: inventory only; broad privileges require contextual review'
inspect /etc/sudoers
for f in /etc/sudoers.d/*; do inspect "$f"; done
if command -v visudo >/dev/null; then visudo -c || warn 'sudoers validation failed'; else warn 'visudo unavailable'; fi
printf 'Review sudoers include directives; custom include paths require manual inspection.\n'
section 'Accounts, UID 0, SSH authorization and user systemd persistence'
printf 'Local UID 0 entries (root itself is expected):\n'
awk -F: '$3 == 0 {print $1 ":uid=" $3 ":gid=" $4 ":home=" $6 ":shell=" $7}' /etc/passwd | sed -n l
printf 'NSS UID 0 entries (enumeration may omit directory accounts):\n'
if command -v getent >/dev/null; then getent passwd | awk -F: '$3 == 0 {print $1 ":" $3 ":" $6 ":" $7}' | sed -n l; fi
# Read local accounts and NSS accounts without assuming home paths have no spaces.
while IFS=: read -r user pass uid gid gecos home shell; do
  [[ $home == /* && -d $home && $home != / ]] || continue
  printf '\nUser %q home %q\n' "$user" "$home"
  for f in "$home"/.ssh/authorized_keys "$home"/.ssh/authorized_keys2 "$home"/.ssh/rc; do [[ -e $f || -L $f ]] && inspect "$f"; done
  for d in "$home"/.config/systemd/user "$home"/.local/share/systemd/user; do scan_units "$d"; done
done < <(if command -v getent >/dev/null; then getent passwd; else cat /etc/passwd; fi)
for d in /run/user/*/systemd/user /run/user/*/systemd/generator*; do scan_units "$d"; done
for f in /var/lib/systemd/linger/*; do inspect "$f"; done
section 'SSH server configuration: includes, custom key paths and commands'
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/ssh/sshrc; do [[ -e $f || -L $f ]] && inspect "$f"; done
printf 'Review Include, Match, AuthorizedKeysFile/Command, TrustedUserCAKeys and principals.\nCustom paths and includes outside these directories require manual inspection.\n'
section 'Recent or hidden files: context only, never cleanup candidates'
((${#ROOTS[@]})) || ROOTS=(/etc /var/spool /usr/local /opt /tmp /var/tmp /root /home)
for d in "${ROOTS[@]}"; do
  [[ -d $d ]] || continue
  printf '\nRoot %q (limit %s)\n' "$d" "$LIMIT"
  count=0
  while IFS= read -r -d '' f; do
    if [[ $f == SCAN_FAILED ]]; then warn "file traversal failed: $d"; continue; fi
    ((count+=1))
    if ((count <= LIMIT)); then printf '%q\n' "$f"; fi
  done < <(find "$d" -xdev \( -type f -o -type l \) \( -newermt "@$SINCE_EPOCH" -o -newerct "@$SINCE_EPOCH" -o -name '.*' -o -path '*/.*/*' \) -print0 || printf 'SCAN_FAILED\0')
  printf 'Matched %s paths; printed at most %s.\n' "$count" "$LIMIT"
done
if ((CLEAN)); then
  section 'Optional cron quarantine; each item requires its exact path'
  for i in "${!CANDIDATES[@]}"; do
    f=${CANDIDATES[i]}
    # Refuse symlinked parents, hard links, non-root ownership or changed evidence.
    [[ -f $f && ! -L $f && $(realpath -e -- "$f") == "$f" ]] || continue
    [[ $(stat -c '%u:%h' -- "$f") == 0:1 ]] || continue
    [[ $(fingerprint "$f") == "${DIGESTS[i]}" ]] || { warn "changed; skipped: $f"; continue; }
    owner "$f" >/dev/null && continue
    printf '\nQuarantine %q? Type the full path to confirm; Enter skips: ' "$f" >/dev/tty
    IFS= read -r answer </dev/tty || break
    [[ $answer == "$f" ]] || continue
    [[ -f $f && ! -L $f && $(realpath -e -- "$f") == "$f" && $(fingerprint "$f") == "${DIGESTS[i]}" ]] || { warn 'item changed; skipped'; continue; }
    # All writes occur only after this individual confirmation. mktemp creates
    # a private unpredictable directory in root-owned /var/lib, not /tmp.
    [[ -d /var/lib && $(realpath -e /var/lib) == /var/lib && $(stat -c %u /var/lib) == 0 ]] || { warn 'unsafe backup parent'; continue; }
    mode=$(stat -c %a /var/lib)
    [[ ${mode: -2:1} == [0145] && ${mode: -1} == [0145] ]] || { warn 'backup parent writable by group/others'; continue; }
    backup=$(umask 077; mktemp -d /var/lib/06-hunt-backup.XXXXXXXX) || { warn 'backup directory failed'; continue; }
    if cp -a -- "$f" "$backup/backup" && cmp -s -- "$f" "$backup/backup" && [[ $(fingerprint "$f") == "${DIGESTS[i]}" ]]; then
      if printf '%s\n' "$f" >"$backup/original-path" && mv -- "$f" "$backup/quarantined"; then printf 'Quarantined; verified backup and original in %q\n' "$backup"
      else warn "quarantine failed; backup retained: $backup"; fi
    else warn "backup verification failed; original retained; inspect $backup"
    fi
  done
fi
printf '\nFinished. Inventory is not a compromise verdict; validate against a known baseline.\n'
exit "$STATUS"
