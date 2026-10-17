#!/bin/bash
# 03-firewall.sh  (checklist step 7: firewall rules for the CCDC Splunk VM)
# Dry run by default:  sudo ./03-firewall.sh [--apply]
# After --apply it ROLLS BACK in 60s unless you type "keep" (so a bad rule can't lock you out).
set -u
[ "$(id -u)" -eq 0 ] || { echo "Run as root."; exit 1; }

# ===== EDIT THESE (space-separated IPs/CIDRs) =====
# Blocking the SCORING ENGINE costs points. Get its IP from the team packet / team lead
# and put it in EXTRA_SRC (it gets SSH, web, forwarder and HEC access).
MGMT_SRC="172.20.242.0/24"   # may SSH in (your team subnet)
WEB_SRC="172.20.242.0/24"    # may reach Splunk web (8000)
FWD_SRC="172.20.242.0/24"    # may send forwarder data (9997) and HEC (8088)
EXTRA_SRC=""                 # scoring engine + any other required hosts
ALLOW_SSH=yes
# ==================================================

APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1
run() { if [ "$APPLY" -eq 1 ]; then echo "+ $*"; "$@"; else echo "[dry-run] $*"; fi; }
SSH_ALLOW="$MGMT_SRC $EXTRA_SRC"; WEB_ALLOW="$WEB_SRC $EXTRA_SRC"; FWD_ALLOW="$FWD_SRC $EXTRA_SRC"
BACKUP=/root/fw-backup-$(date +%s).rules

if [ "$APPLY" -eq 1 ] && [ -z "$EXTRA_SRC" ]; then
  read -r -p "EXTRA_SRC (scoring engine) is empty. Continue anyway? [y/N] " yn
  [ "$yn" = y ] || { echo "Aborted. Set EXTRA_SRC and rerun."; exit 1; }
fi

if command -v firewall-cmd >/dev/null; then
  firewall-cmd --state >/dev/null 2>&1 || run systemctl enable --now firewalld
  MODE=firewalld
elif command -v iptables >/dev/null; then MODE=iptables
else echo "Neither firewalld nor iptables is installed."; exit 1; fi
echo "Using: $MODE"

docker_user() {
  { command -v iptables >/dev/null && iptables -L DOCKER-USER -n >/dev/null 2>&1; } || return 0
  echo "-- Docker-published ports skip INPUT, so filter them in DOCKER-USER"
  for spec in "8000:$WEB_ALLOW" "9997:$FWD_ALLOW" "8088:$FWD_ALLOW" "8089:127.0.0.1/32"; do
    port=${spec%%:*}; srcs=${spec#*:}
    run iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport "$port" --ctdir ORIGINAL -j DROP
    for s in $srcs; do
      run iptables -I DOCKER-USER -s "$s" -p tcp -m conntrack --ctorigdstport "$port" --ctdir ORIGINAL -j ACCEPT
    done
  done
}

fw_firewalld() {
  for svc in $(firewall-cmd --zone=public --list-services 2>/dev/null); do
    run firewall-cmd --zone=public --remove-service="$svc"
  done
  if [ "$ALLOW_SSH" = yes ]; then
    for s in $SSH_ALLOW; do run firewall-cmd --zone=public --add-rich-rule="rule family=ipv4 source address=$s service name=ssh accept"; done
  fi
  for s in $WEB_ALLOW; do run firewall-cmd --zone=public --add-rich-rule="rule family=ipv4 source address=$s port port=8000 protocol=tcp accept"; done
  for p in 9997 8088; do
    for s in $FWD_ALLOW; do run firewall-cmd --zone=public --add-rich-rule="rule family=ipv4 source address=$s port port=$p protocol=tcp accept"; done
  done
  docker_user
}

fw_iptables() {
  run iptables -F INPUT
  run iptables -A INPUT -i lo -j ACCEPT
  run iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  run iptables -A INPUT -p icmp -j ACCEPT
  if [ "$ALLOW_SSH" = yes ]; then
    for s in $SSH_ALLOW; do run iptables -A INPUT -p tcp --dport 22 -s "$s" -j ACCEPT; done
  fi
  for s in $WEB_ALLOW; do run iptables -A INPUT -p tcp --dport 8000 -s "$s" -j ACCEPT; done
  for p in 9997 8088; do
    for s in $FWD_ALLOW; do run iptables -A INPUT -p tcp --dport "$p" -s "$s" -j ACCEPT; done
  done
  run iptables -P INPUT DROP
  docker_user
  if command -v ip6tables >/dev/null; then
    run ip6tables -F INPUT
    run ip6tables -A INPUT -i lo -j ACCEPT
    run ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    run ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
    run ip6tables -P INPUT DROP
  fi
}

rollback() {
  echo "Rolling back..."
  [ "$MODE" = firewalld ] && firewall-cmd --reload
  [ -f "$BACKUP" ] && iptables-restore < "$BACKUP"
  if command -v ip6tables >/dev/null; then ip6tables -P INPUT ACCEPT; ip6tables -F INPUT; fi
}

[ "$APPLY" -eq 1 ] && command -v iptables-save >/dev/null && { iptables-save > "$BACKUP"; echo "Backup saved: $BACKUP"; }
if [ "$MODE" = firewalld ]; then fw_firewalld; else fw_iptables; fi

if [ "$APPLY" -eq 1 ]; then
  echo
  echo "Rules applied. TEST NOW: SSH, Splunk web, and ask a teammate to check the scoreboard."
  read -r -t 60 -p "Type 'keep' within 60s to keep them, anything else rolls back: " ans || true
  echo
  if [ "${ans:-}" = keep ]; then
    if [ "$MODE" = firewalld ]; then
      firewall-cmd --runtime-to-permanent && echo "Saved permanently."
    else
      echo "Kept until reboot. To persist (RHEL/Oracle): dnf install -y iptables-services && systemctl enable iptables && service iptables save"
    fi
  else
    rollback
  fi
else
  echo; echo "Dry run only. Re-run with --apply to make changes."
fi
