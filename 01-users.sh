#!/bin/bash
# Interactive CCDC User Account Auditor & Remediation Tool
# Must be run as root

set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[-] Error: This script must be run as root." >&2
    exit 1
fi

echo "=========================================================="
echo "  CCDC Interactive User Account Review & Triage"
echo "  Time: $(date)"
echo "=========================================================="

# Iterate through all users in /etc/passwd
while IFS=: read -r user passwd uid gid gecos home shell; do
    # Skip non-numeric UIDs just in case
    [[ $uid =~ ^[0-9]+$ ]] || continue

    # AUTOMATIC FILTER: Skip standard system accounts (UID < 1000), 
    # but KEEP UID 0 accounts so you can review extra root accounts!
    if ((uid < 1000 && uid > 0)); then
        continue
    fi

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

    # Fixed syntax: use proper string comparison for user name
    if ((uid == 0)) && [[ "$user" != "root" ]]; then
        echo "    [!] CRITICAL WARNING: Extra account with UID 0 (Root privileges!)"
    fi

    # Interactive Prompt for real users (UID >= 1000 or extra UID 0)
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
