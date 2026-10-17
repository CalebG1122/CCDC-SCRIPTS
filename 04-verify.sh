#!/bin/bash
# 04-verify.sh  (checklist steps 4, 6, 8 plus a quick persistence audit)
# Run:  sudo ./04-verify.sh | tee ~/verify-$(date +%F-%H%M).txt
[ "$(id -u)" -eq 0 ] || { echo "Run as root."; exit 1; }
sec() { printf '\n===== %s =====\n' "$*"; }

sec "Who is logged in"; who; echo; last -n 10 2>/dev/null
sec "UID 0 accounts"; awk -F: '$3==0{print $1}' /etc/passwd
sec "Regular users and shells"; awk -F: '$3>=1000 && $3<60000{print $1" -> "$7}' /etc/passwd
sec "Admin groups"; getent group wheel; getent group sudo
sec "sudoers (active lines)"; grep -rhn '^[^#[:space:]]' /etc/sudoers /etc/sudoers.d 2>/dev/null

sec "Enabled services"; systemctl list-unit-files --type=service --state=enabled --no-pager
sec "Listening ports"; ss -tlnup

sec "iptables -L -v -n"; iptables -L -v -n 2>&1
sec "nft list ruleset"; nft list ruleset 2>&1 | head -100
sec "firewall-cmd --list-all"; firewall-cmd --list-all 2>&1
sec "firewall-cmd --permanent --list-all-zones"; firewall-cmd --permanent --list-all-zones 2>&1 | head -60

sec "Docker containers"; docker ps 2>&1

sec "Persistence audit: cron"
ls -l /etc/cron.d /etc/cron.daily /var/spool/cron 2>/dev/null
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
sec "Persistence audit: SSH authorized_keys"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done
sec "Persistence audit: files in /etc changed in the last day"
find /etc -xdev -type f -mtime -1 2>/dev/null | head -50
sec "Persistence audit: SUID binaries (look for oddballs)"
find / -xdev -perm -4000 -type f 2>/dev/null
