#!/bin/bash
# 01-users.sh  (checklist steps 1-4: passwords, who, permissions, verify)
# Dry run by default:  sudo ./01-users.sh            -> shows what it WOULD do
#                      sudo ./01-users.sh --apply    -> makes the changes
set -u
[ "$(id -u)" -eq 0 ] || { echo "Run as root."; exit 1; }

# ===== EDIT THESE FIRST =====
KEEP_ADMINS="root"   # accounts allowed to keep sudo/wheel (include YOUR account)
KEEP_LOGIN="root"    # accounts allowed to keep a login shell (include scored/service users!)
CHANGE_PW="root"     # accounts to set a new password for (you'll be prompted)
# ============================

APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1
run() { if [ "$APPLY" -eq 1 ]; then echo "+ $*"; "$@"; else echo "[dry-run] $*"; fi; }
in_list() { case " $2 " in *" $1 "*) return 0;; esac; return 1; }
getent group wheel >/dev/null && ADMIN_GRP=wheel || ADMIN_GRP=sudo
NOLOGIN=$(command -v nologin || echo /usr/sbin/nologin)

echo "== 1. Change passwords =="
for u in $CHANGE_PW; do
  if id "$u" >/dev/null 2>&1; then run passwd "$u"; else echo "skip: no user $u"; fi
done

echo; echo "== 2. Who is logged in =="
who

echo; echo "== 3. Fix permissions =="
echo "-- remove $ADMIN_GRP members not on the keep list:"
for u in $(getent group "$ADMIN_GRP" | cut -d: -f4 | tr ',' ' '); do
  in_list "$u" "$KEEP_ADMINS" || run gpasswd -d "$u" "$ADMIN_GRP"
done
echo "-- disable login shell for regular users not on the keep list:"
while IFS=: read -r u _ uid _ _ _ shell; do
  [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] || continue
  case "$shell" in */nologin|*/false) continue;; esac
  in_list "$u" "$KEEP_LOGIN" || run usermod -s "$NOLOGIN" "$u"
done < /etc/passwd
echo "-- report only (review by hand):"
awk -F: '$3==0 && $1!="root"{print "EXTRA UID 0 ACCOUNT: "$1}' /etc/passwd
grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d 2>/dev/null || echo "no NOPASSWD rules found"
ls -l /etc/sudoers.d 2>/dev/null

echo; echo "== 4. Verify =="
echo "$ADMIN_GRP members: $(getent group "$ADMIN_GRP" | cut -d: -f4)"
awk -F: '$3>=1000 && $3<60000{print $1" -> "$7}' /etc/passwd

[ "$APPLY" -eq 0 ] && echo && echo "Dry run only. Re-run with --apply to make changes."
