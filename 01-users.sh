#!/bin/bash
# Explicit account operations; dry-run by default. Bash 4+, Linux.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
usage() {
  cat <<'EOF'
Usage: 01-users.sh [--verbose] [--apply] [--restrict-admins --keep-admin USER ...]
                   [--restrict-logins --keep-login USER ...] [--password USER ...]
Without restriction flags, only inventory is performed. Each restriction requires
an explicit keep list. Root and the invoking sudo user are always protected.
Both wheel and sudo are inspected. Primary-group admin grants and sudoers grants
are reported for manual review, not rewritten. Each change requires confirmation.
EOF
}
APPLY=0 ADMINS=0 LOGINS=0 STATUS=0 BACKUP='' VERBOSE=0 LOGIN_COUNT=0
KEEP_ADMINS=(root) KEEP_LOGIN=(root) PASSWORDS=()
ADMIN_ARGS=0 LOGIN_ARGS=0
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
while (($#)); do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --apply) APPLY=1 ;;
    --verbose) VERBOSE=1 ;;
    --restrict-admins) ADMINS=1 ;;
    --restrict-logins) LOGINS=1 ;;
    --keep-admin|--keep-login|--password)
      (($# >= 2)) || die "$1 needs a username"
      [[ $2 =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]] || die 'invalid username'
      case $1 in
        --keep-admin) KEEP_ADMINS+=("$2"); ADMIN_ARGS=1 ;;
        --keep-login) KEEP_LOGIN+=("$2"); LOGIN_ARGS=1 ;;
        --password) PASSWORDS+=("$2") ;;
      esac; shift ;;
    *) die "unknown option: $1" ;;
  esac; shift
done
(( ! ADMINS || ADMIN_ARGS )) || die '--restrict-admins requires --keep-admin'
(( ! LOGINS || LOGIN_ARGS )) || die '--restrict-logins requires --keep-login'
(( ! APPLY || EUID == 0 )) || die '--apply requires root'
if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
  KEEP_ADMINS+=("$SUDO_USER"); KEEP_LOGIN+=("$SUDO_USER")
fi
contains() { local wanted=$1 entry; shift; for entry in "$@"; do [[ $entry != "$wanted" ]] || return 0; done; return 1; }
for u in "${KEEP_ADMINS[@]}" "${KEEP_LOGIN[@]}" "${PASSWORDS[@]}"; do
  getent passwd "$u" >/dev/null || die "unknown account: $u"
done
NOLOGIN=$(command -v nologin) || die 'nologin unavailable'
[[ -x $NOLOGIN ]] || die 'nologin not executable'
backup() {
  [[ -z $BACKUP ]] || return 0
  [[ -d /var/lib && ! -L /var/lib ]] || die 'unsafe backup parent'
  BACKUP=$(umask 077; mktemp -d /var/lib/ccdc-users.XXXXXXXX)
  chmod 700 "$BACKUP"
  for file in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do
    [[ ! -e $file ]] || cp -a -- "$file" "$BACKUP/"
  done
  printf 'Private account backup: %s (contains password hashes)\n' "$BACKUP"
}
change() {
  local label=$1 answer; shift
  printf '\nProposed: %s\n' "$label"
  printf '  '; printf '%q ' "$@"; printf '\n'
  ((APPLY)) || return 0
  [[ -t 0 && -t 1 ]] || die '--apply changes require an interactive terminal'
  printf 'Type yes to apply this item: '; IFS= read -r answer || return 0
  [[ $answer == yes ]] || return 0
  backup
  if ! "$@"; then printf 'FAILED: %s\n' "$label" >&2; STATUS=1; fi
}
if ((VERBOSE)); then printf 'Logged-in users:\n'; who || STATUS=1; fi
printf 'Account review\n'
awk -F: '$3 == 0 && $1 != "root" {print "REVIEW: extra UID 0 account: " $1; n++} END {if (!n) print "Extra UID 0 accounts: none in local passwd"}' /etc/passwd
for group in wheel sudo; do
  record=$(getent group "$group") || continue
  IFS=: read -r name unused admin_gid members <<< "$record"
  printf '\nAdmin group %s: %s\n' "$name" "$members"
  while IFS=: read -r user unused uid gid rest; do
    if [[ $gid == "$admin_gid" && $user != root ]]; then
      printf 'REVIEW: %s has primary admin group %s; no automatic primary-group change.\n' "$user" "$group"
    fi
  done < /etc/passwd
  IFS=, read -r -a users <<< "$members"
  for user in "${users[@]}"; do
    [[ -n $user ]] || continue
    if ((ADMINS)) && ! contains "$user" "${KEEP_ADMINS[@]}"; then
      change "Remove supplementary $group membership from $user" gpasswd -d "$user" "$group"
    fi
  done
done
while IFS=: read -r user unused uid gid gecos home shell; do
  [[ $uid =~ ^[0-9]+$ ]] || continue
  ((uid >= 1000 && uid < 60000)) || continue
  ((LOGIN_COUNT+=1))
  if ((VERBOSE)); then printf 'Login account: %s -> %s\n' "$user" "$shell"; fi
  case $shell in */nologin|*/false) continue ;; esac
  if ((LOGINS)) && ! contains "$user" "${KEEP_LOGIN[@]}"; then
    change "Set nologin for $user (does not terminate sessions or revoke SSH forwarding)" usermod -s "$NOLOGIN" "$user"
  fi
done < /etc/passwd
printf 'Regular local accounts checked: %s\n' "$LOGIN_COUNT"
for user in "${PASSWORDS[@]}"; do change "Change password for $user" passwd "$user"; done
printf '\nReview effective sudoers grants, includes and directory/NSS accounts separately.\n'
if ((EUID == 0)); then
  if command -v visudo >/dev/null; then
    if ((VERBOSE)); then visudo -c || STATUS=1
    else visudo -c >/dev/null || STATUS=1; fi
  else printf 'INCOMPLETE: visudo unavailable\n' >&2; STATUS=1; fi
fi
((APPLY)) || printf 'Dry run; no changes made.\n'
((VERBOSE)) || printf 'Use --verbose for full account listings.\n'
exit "$STATUS"
