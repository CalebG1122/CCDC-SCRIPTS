#!/bin/bash
# Ultimate CCDC Interactive User Account Auditor & Remediation Tool
# Uses getent passwd, audits group memberships, shells, UIDs, and shadow status.
# Must be run as root.

set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[-] Error: This script must be run as root." >&2
    exit 1
fi

echo "=========================================================="
echo "  CCDC Ultimate User Account Auditor & Triage"
echo "  Time: $(date)"
echo "=========================================================="

# Iterate through all accounts using getent passwd (covers local, NSS, LDAP, SSSD)
while IFS=: read -r user passwd uid gid gecos home shell; do
    [[ $uid =~ ^[0-9]+$ ]] || continue

    # Gather user intelligence
    groups_list=$(id -Gn "$user" 2>/dev/null | tr ' ' ',')
    last_login=$(lastlog -u "$user" 2>/dev/null | tail -n 1 || echo "No login data")
    shadow_status=$(passwd -S "$user" 2>/dev/null | awk '{print $2 " (" $3 " days password age)"}' || echo "Status unknown")

    risk_flags=()

    # 1. Check for extra UID 0 accounts
    if ((uid == 0)) && [[ "$user" != "root" ]]; then
        risk_flags+=("CRITICAL: Extra account with UID 0 (Full Root Privileges!)")
    fi

    # 2. Check for Low-UID (< 1000) anomalies
    if ((uid > 0 && uid < 1000)); then
        case "$shell" in
            */nologin|*/false)
                # If it's a standard system account, check if it illegally belongs to an admin group
                if [[ "$groups_list" =~ (^|,)(wheel|sudo)(,|$) ]]; then
                    risk_flags+=("SUSPICIOUS: Low-UID system account belongs to a privileged group ($groups_list)")
                else
                    # Clean system daemon, auto-skip to reduce competition noise
                    continue
                fi
                ;;
            *)
                risk_flags+=("SUSPICIOUS: Low-UID account (<1000) has an interactive shell ($shell)")
                ;;
        esac
    fi

    # 3. Check regular accounts (UID >= 1000) for admin group membership
    if ((uid >= 1000)); then
        if [[ "$groups_list" =~ (^|,)(wheel|sudo)(,|$) ]]; then
            risk_flags+=("NOTICE: User has administrative (wheel/sudo) access")
        fi
    fi

    # Display Account Profile
    echo ""
    echo "--------------------------------------------------"
    echo "[*] Account Found: $user"
    echo "    UID:      $uid | GID: $gid"
    echo "    Home:     $home"
    echo "    Shell:    $shell"
    echo "    Groups:   $groups_list"
    echo "    Login:    $last_login"
    echo "    Shadow:   $shadow_status"

    # Display Risk Flags if any exist
    if (( ${#risk_flags[@]} > 0 )); then
        echo "    [!] SECURITY FLAGS:"
        for flag in "${risk_flags[@]}"; do
            echo "        -> $flag"
        . done 2>/dev/null || echo "        -> $flag"
        fi
    else
        echo "    [i] Profile looks standard."
    fi

    # Interactive Triage Prompt
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

done < <(getent passwd)

echo ""
echo "=========================================================="
echo "  Ultimate account review complete!"
echo "=========================================================="
