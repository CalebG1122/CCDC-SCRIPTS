#!/bin/bash
# Source-restricted INPUT and Docker rules with an independent rollback timer.
# Linux, Bash 4+, Python 3, iptables/ip6tables, GNU timeout/flock, systemd required.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
usage() {
  cat <<'EOF'
Usage: 03-firewall.sh --management-source CIDR [repeatable]
       [--web-source CIDR ...] [--forwarder-source CIDR ...]
       (--scoring-source CIDR ... | --no-scoring)
       [--ssh-port PORT] [--no-ssh --console] [--apply] [--verbose]
Default prints a short read-only plan. --verbose shows every rule command.
Web/forwarder sources default to management
sources. Scoring sources can reach SSH, web (8000), forwarder (9997), HEC (8088).
IPv4 and IPv6 CIDRs are supported. Missing IPv6 allowances deny new IPv6 service
connections. Existing connections, loopback and ICMP remain allowed. Port 8089
is not exposed. Outbound and unrelated forwarding rules remain unchanged.

--apply requires root, a terminal, working systemd and BOTH firewall families.
It saves both rulesets and arms a 90-second systemd rollback BEFORE changes.
Type keep after testing a NEW SSH session and scored services, within 60 seconds.
Successful rules are runtime-only. Backups and a manual rollback script remain.
Do not modify firewall/Docker configuration concurrently during the transaction.

Managed firewalls (active firewalld/UFW) are deliberately refused on apply: this
script cannot safely snapshot/restore their complete runtime and permanent state.
It does not stop, disable, reload or persist another firewall manager.
EOF
}
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
APPLY=0 SCORING_ACK=0 NO_SSH=0 CONSOLE=0 SSH_PORT=22 VERBOSE=0
MGMT=() WEB=() FWD=() SCORE=()
while (($#)); do
  case $1 in
    --help|-h) usage; exit 0 ;;
    --apply) APPLY=1 ;;
    --verbose) VERBOSE=1 ;;
    --no-scoring) SCORING_ACK=1 ;;
    --no-ssh) NO_SSH=1 ;;
    --console) CONSOLE=1 ;;
    --management-source|--web-source|--forwarder-source|--scoring-source|--ssh-port)
      (($# >= 2)) || die "$1 requires a value"
      case $1 in
        --management-source) MGMT+=("$2") ;;
        --web-source) WEB+=("$2") ;;
        --forwarder-source) FWD+=("$2") ;;
        --scoring-source) SCORE+=("$2"); SCORING_ACK=1 ;;
        --ssh-port) SSH_PORT=$2 ;;
      esac; shift ;;
    *) die "unknown option: $1" ;;
  esac; shift
done
((${#MGMT[@]})) || die '--management-source is required'
((SCORING_ACK)) || die 'specify scoring sources or explicitly use --no-scoring'
[[ $SSH_PORT =~ ^[1-9][0-9]{0,4}$ ]] && ((SSH_PORT <= 65535)) || die 'SSH port must be 1..65535'
if ((NO_SSH)); then
  ((CONSOLE)) && [[ -z ${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-} ]] || die '--no-ssh requires --console from a local console'
fi
((${#WEB[@]})) || WEB=("${MGMT[@]}")
((${#FWD[@]})) || FWD=("${MGMT[@]}")
command -v python3 >/dev/null || die 'Python 3 required for IP/CIDR validation'
normalize() {
  python3 - "$@" <<'PY'
import ipaddress, sys
if len(sys.argv) > 129:
    sys.exit('At most 128 sources per list')
for value in sys.argv[1:]:
    try:
        network = ipaddress.ip_network(value, strict=False)
        if '%' in str(network):
            raise ValueError('scope identifiers not supported')
    except ValueError as error:
        sys.exit('Invalid source %r: %s' % (value, error))
    print(network.version, network)
PY
}
# Command substitutions propagate validation failure; no process-substitution loss.
mgmt=$(normalize "${MGMT[@]}") || die 'invalid management sources'
web=$(normalize "${WEB[@]}") || die 'invalid web sources'
fwd=$(normalize "${FWD[@]}") || die 'invalid forwarder sources'
score=$(normalize "${SCORE[@]}") || die 'invalid scoring sources'
if [[ -n ${SSH_CONNECTION:-} ]] && ((!NO_SSH)); then
  remote=${SSH_CONNECTION%% *}
  python3 - "$remote" "$mgmt" "$score" <<'PY'
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
networks = [ipaddress.ip_network(line.split()[1]) for value in sys.argv[2:] for line in value.splitlines()]
if not any(address.version == n.version and address in n for n in networks):
    sys.exit('Current SSH client is outside the management/scoring allowlists')
PY
fi
# Emit shell-escaped commands from fixed verbs and validated values only.
emit() { printf '%q ' "$@"; printf '\n'; }
allow() {
  local program=$1 chain=$2 family=$3 port=$4 values=$5 docker=$6 v source
  while read -r v source; do
    [[ $v == "$family" ]] || continue
    if ((docker)); then
      emit "$program" -w 5 -A "$chain" -s "$source" -p tcp -m conntrack --ctdir ORIGINAL --ctorigdstport "$port" -j RETURN
    else emit "$program" -w 5 -A "$chain" -s "$source" -p tcp --dport "$port" -j ACCEPT; fi
  done <<< "$values"
}
plan_family() {
  local program=$1 family=$2 docker=$3 host_chain=$4 docker_chain=$5
  emit "$program" -w 5 -N "$host_chain"
  emit "$program" -w 5 -A "$host_chain" -i lo -j ACCEPT
  emit "$program" -w 5 -A "$host_chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  if [[ $family == 4 ]]; then emit "$program" -w 5 -A "$host_chain" -p icmp -j ACCEPT
  else emit "$program" -w 5 -A "$host_chain" -p ipv6-icmp -j ACCEPT; fi
  if ((!NO_SSH)); then allow "$program" "$host_chain" "$family" "$SSH_PORT" "$mgmt"$'\n'"$score" 0; fi
  allow "$program" "$host_chain" "$family" 8000 "$web"$'\n'"$score" 0
  for port in 9997 8088; do allow "$program" "$host_chain" "$family" "$port" "$fwd"$'\n'"$score" 0; done
  emit "$program" -w 5 -A "$host_chain" -j DROP
  # Attach a fully populated chain ahead of existing broad INPUT allowances.
  emit "$program" -w 5 -I INPUT 1 -j "$host_chain"
  if ((docker)); then
    emit "$program" -w 5 -N "$docker_chain"
    emit "$program" -w 5 -A "$docker_chain" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    allow "$program" "$docker_chain" "$family" 8000 "$web"$'\n'"$score" 1
    for port in 9997 8088; do allow "$program" "$docker_chain" "$family" "$port" "$fwd"$'\n'"$score" 1; done
    for port in 8000 9997 8088 8089; do
      emit "$program" -w 5 -A "$docker_chain" -p tcp -m conntrack --ctdir ORIGINAL --ctorigdstport "$port" -j DROP
    done
    emit "$program" -w 5 -A "$docker_chain" -j RETURN
    emit "$program" -w 5 -I DOCKER-USER 1 -j "$docker_chain"
  fi
}
if ((!APPLY)); then
  if ((!VERBOSE)); then
    printf 'Firewall plan only; no changes made.\n'
    printf 'Management sources: %s | Web: %s | Forwarder: %s | Scoring: %s\n' "${#MGMT[@]}" "${#WEB[@]}" "${#FWD[@]}" "${#SCORE[@]}"
    if ((NO_SSH)); then printf 'New SSH connections: denied.\n'
    else printf 'SSH port %s: management/scoring sources only.\n' "$SSH_PORT"; fi
    printf 'Ports 8000/9997/8088: selected sources only; external 8089 denied.\n'
    printf 'Other new inbound traffic denied; existing sessions/loopback/ICMP allowed.\n'
    printf 'IPv4 and IPv6 covered; Docker rules require DOCKER-USER hooks.\n'
    printf 'Use --verbose for every rule, or --apply for confirmed runtime changes.\n'
    exit 0
  fi
  printf '# Plan only; no firewall queries, temporary files or writes.\n'
  printf '# Docker rules shown conditionally; installed only where DOCKER-USER exists.\n'
  plan_family iptables 4 1 CCDC_INPUT_PLAN CCDC_DOCKER_PLAN
  plan_family ip6tables 6 1 CCDC_INPUT_PLAN CCDC_DOCKER_PLAN
  exit 0
fi
((EUID == 0)) || die '--apply requires root'
[[ -t 0 && -t 1 ]] || die '--apply requires an interactive terminal'
for tool in iptables ip6tables iptables-save ip6tables-save iptables-restore ip6tables-restore systemd-run systemctl timeout flock mktemp; do
  command -v "$tool" >/dev/null || die "required tool unavailable: $tool"
done
[[ -d /run/systemd/system ]] || die 'working systemd is required for independent rollback'
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then die 'active firewalld: use its native configuration; no changes made'; fi
if command -v ufw >/dev/null; then
  ufw_state=$(ufw status) || die 'cannot determine UFW status'
  [[ $ufw_state != *'Status: active'* ]] || die 'active UFW: use its native configuration; no changes made'
fi
for manager in firewalld ufw; do
  if systemctl is-active --quiet "$manager.service"; then die "active $manager service; no changes made"; fi
done
umask 077
exec 9>/run/lock/ccdc-firewall.lock
flock -n 9 || die 'another CCDC firewall transaction is running'
# Reject another live watchdog, including one left by a disconnected shell.
active=$(systemctl list-units --all --plain --no-legend 'ccdc-fw-*.timer') || die 'cannot inspect rollback timers'
[[ -z $active ]] || die 'a previous CCDC rollback timer exists; inspect it before retrying'
backup=$(mktemp -d /var/lib/ccdc-firewall.XXXXXXXX)
printf 'Private rollback directory: %s\n' "$backup"
iptables-save > "$backup/ipv4.rules"
ip6tables-save > "$backup/ipv6.rules"
[[ -s $backup/ipv4.rules && -s $backup/ipv6.rules ]] || die 'empty firewall snapshot'
iptables-restore --test < "$backup/ipv4.rules"
ip6tables-restore --test < "$backup/ipv6.rules"
docker4=0 docker6=0
iptables -w 5 -S DOCKER-USER >/dev/null 2>&1 && docker4=1
ip6tables -w 5 -S DOCKER-USER >/dev/null 2>&1 && docker6=1
if systemctl is-active --quiet docker.service && ((!docker4)); then die 'Docker is active without an IPv4 DOCKER-USER hook; unsupported forwarding backend'; fi
if grep -q DOCKER "$backup/ipv6.rules" && ((!docker6)); then die 'IPv6 Docker rules have no DOCKER-USER hook'; fi
suffix=$(date +%s)_$$
host_chain=CCDC_I_$suffix docker_chain=CCDC_D_$suffix
{
  printf '#!/bin/bash\nset -Eeuo pipefail\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C\n'
  plan_family "$(command -v iptables)" 4 "$docker4" "$host_chain" "$docker_chain"
  plan_family "$(command -v ip6tables)" 6 "$docker6" "$host_chain" "$docker_chain"
} > "$backup/apply.sh"
# No user-controlled configuration is sourced. This generated helper is private.
cat > "$backup/rollback.sh" <<'ROLLBACK'
#!/bin/bash
set -uo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
dir=${0%/*}
exec 8>"$dir/state.lock"
flock -x 8
state=$(cat "$dir/state") || exit 1
[[ $state != committed && $state != restored ]] || exit 0
status=0
iptables-restore -w 5 < "$dir/ipv4.rules" || status=1
ip6tables-restore -w 5 < "$dir/ipv6.rules" || status=1
if ((status == 0)); then printf 'restored\n' > "$dir/state"
else printf 'restore-failed\n' > "$dir/state"; fi
exit "$status"
ROLLBACK
bash -n "$backup/apply.sh"
bash -n "$backup/rollback.sh"
printf 'pending\n' > "$backup/state"
unit=ccdc-fw-$(date +%s)-$$
armed=0 committed=0
finish() {
  local code=$?
  trap - EXIT HUP INT TERM
  # If killed with SIGKILL, systemd still runs the independent helper.
  if ((armed && !committed)); then
    # Release foreground state lock before attempting synchronous rollback.
    flock -u 8 2>/dev/null || true
    if bash "$backup/rollback.sh"; then
      systemctl stop "$unit.timer" || true
      printf 'Original IPv4 and IPv6 rules restored. Backup: %s\n' "$backup" >&2
    else printf 'ROLLBACK FAILED: %s; watchdog remains armed.\n' "$backup/rollback.sh" >&2; code=1; fi
  fi
  exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
start=$SECONDS
systemd-run --quiet --unit="$unit" --on-active=90s --timer-property=AccuracySec=1s --property=Type=oneshot --property=Restart=on-failure --property=RestartSec=5s /bin/bash "$backup/rollback.sh"
armed=1
systemctl is-active --quiet "$unit.timer" || die 'rollback timer failed to arm'
printf 'Watchdog armed. Applying rules with a 30-second hard limit.\n'
exec 8>"$backup/state.lock"
flock -x 8
timeout --kill-after=5s 30s bash "$backup/apply.sh"
printf 'applied\n' > "$backup/state"
flock -u 8
printf 'Test a NEW SSH session, web/ingestion and scoring now.\nType keep within 60 seconds; anything else rolls back: '
answer=''
IFS= read -r -t 60 answer || true
if [[ $answer == keep ]]; then
  flock -x 8
  [[ $(cat "$backup/state") == applied ]] && ((SECONDS - start < 89)) || die 'rollback deadline reached or watchdog already ran'
  printf 'committed\n' > "$backup/state"
  committed=1
  flock -u 8
  systemctl stop "$unit.timer"
  printf 'Kept runtime rules. No reboot persistence was changed. Backup: %s\n' "$backup"
  printf 'To restore later, reset state to pending and run rollback.sh from the private backup directory.\n'
else printf '\nNot confirmed; restoring original rules.\n'; exit 1; fi
