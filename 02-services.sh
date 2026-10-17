#!/bin/bash
# 02-services.sh  (checklist steps 5-6: turn off unneeded services, then inspect the rest)
# Dry run by default:  sudo ./02-services.sh [--apply] [--no-ssh] [--purge]
#   --no-ssh  also disables sshd (ONLY if you have console access and the comp doesn't score SSH)
#   --purge   also uninstalls the packages in PKGS
set -u
[ "$(id -u)" -eq 0 ] || { echo "Run as root."; exit 1; }

# ===== EDIT: anything the comp SCORES must NOT be in these lists =====
KILL="telnet.socket rsh.socket rlogin.socket rexec.socket tftp.socket vsftpd proftpd cups avahi-daemon bluetooth rpcbind nfs-server smb nmb snmpd"
PKGS="telnet-server rsh-server vsftpd tftp-server"
# =====================================================================

APPLY=0; NOSSH=0; PURGE=0
for a in "$@"; do case "$a" in --apply) APPLY=1;; --no-ssh) NOSSH=1;; --purge) PURGE=1;; esac; done
run() { if [ "$APPLY" -eq 1 ]; then echo "+ $*"; "$@"; else echo "[dry-run] $*"; fi; }
[ "$NOSSH" -eq 1 ] && KILL="$KILL sshd ssh ssh.socket"

echo "== 5. Disable unneeded services =="
for s in $KILL; do
  if systemctl cat "$s" >/dev/null 2>&1; then
    run systemctl disable --now "$s"
    run systemctl mask "$s"
  else
    echo "skip (not installed): $s"
  fi
done

if [ "$PURGE" -eq 1 ]; then
  echo; echo "-- removing packages"
  if command -v dnf >/dev/null; then run dnf remove -y $PKGS
  elif command -v apt-get >/dev/null; then run apt-get purge -y $PKGS
  fi
fi

echo; echo "== 6. Inspect what is left =="
echo "-- enabled services:"
systemctl list-unit-files --type=service --state=enabled --no-pager
echo; echo "-- running services:"
systemctl list-units --type=service --state=running --no-pager
echo; echo "-- listening ports:"
ss -tlnup

[ "$APPLY" -eq 0 ] && echo && echo "Dry run only. Re-run with --apply to make changes."
