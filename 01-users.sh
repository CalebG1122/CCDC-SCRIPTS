#!/bin/bash
# Interactive CCDC User Account Auditor & Remediation Tool
# Must be run as root

set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[-] Error: This script must be run as root." >&2
    exit 1
fi

# Protect critical accounts automatically
PROTECTED_USERS=("root" "${SUDO_USER:-$USER}" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network" "systemd-resolve" "syslog" "messagebus" "_apt" "uuidd" "dnsmasq" "landscape" "polkitd" "sshd" "splunk")

echo "=========================================================="
echo "  CCDC Interactive User Account Review & Triage"
echo "  Time: $(date)"
echo "=========================================================="

# Iterate through all users in /etc/passwd
while IFS=: read -r user passwd uid gid gecos home shell; do
    # Skip non-numeric UIDs just in case
    [[ $uid =~ ^[0-9]+$ ]] || continue

    # Check if user is protected
    is_protected=0
    for p in "${PROTECTED_USERS[@]}"; do
        if [[ $user == "$p" ]]; then
            is_protected=1
            break
        fi
    done

    # Gather user details
    groups_list=$(id -Gn "$user" 2>/dev/null | tr ' ' ',')
    last_login=$(lastlog -u "$user" 2>/dev/null | tail -n 1 || echo "No login data")

    echo ""
    echo "--------------------------------------------------"
    echo "[*] Account Found: $user"
    echo "    UID:      $uid | GID: $gid"
    echo "    Home:     $home"
    echo "    Shell:    $shell"
    echo "    Groups:   $groups_list"
    echo "    Status:   $last_login"
    
    if ((is_protected)); then
        echo "    [i] Protected system account. Skipping interactive prompt."
        continue
    fi

    # Highlight extra UID 0 accounts immediately
    if ((uid == 0)); then
        echo "    [!] WARNING: This account has UID 0 (Root privileges!)"
    fi

    # Interactive Prompt
    while true; do
        read -p "Action for [$user] - [K]eep / [L]ock (nologin) / [R]emove user / [D]elete + home / [S]kip? " choice </dev/tty
        case "$choice" in
            [Kk]* )
                echo "    -> Keeping $user."
                break
                ;;
            [Ll]* )
                echo "    -> Locking $user (setting shell to nologin)..."
                usermod -s "$(command -v nologin)" "$user"
                echo "    -> Locked."
                break
                ;;
            [Rr]* )
                read -p "Are you sure you want to delete user $user? (yes/no): " confirm </dev/tty
                if [[ $confirm == "yes" ]]; then
                    userdel "$user"
                    echo "    -> User $user removed."
                else
                    echo "    -> Aborted removal."
                fi
                break
                ;;
            [Dd]* )
                read -p "Are you sure you want to delete user $user AND their home directory? (yes/no): " confirm </dev/tty
                if [[ $confirm == "yes" ]]; then
                    userdel -r "$user"
                    echo "    -> User $user and home directory removed."
                else
                    echo "    -> Aborted deletion."
                fi
                break
                ;;
            [Ss]* )
                echo "    -> Skipped $user."
                break
                ;;
            * )
                echo "Please answer K (Keep), L (Lock), R (Remove user), D (Delete + home), or S (Skip)."
                ;;
        esac
    done

done < /etc/passwd

echo ""
echo "=========================================================="
echo "  Account review complete!"
echo "=========================================================="
