#!/bin/bash
# Fetch one explicitly selected, immutable commit. Never execute stale downloads.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
usage() {
  cat <<'EOF'
Usage: get.sh --ref FULL_COMMIT_SHA [--baseline]
Downloads the four existing scripts into a NEW private directory in the current
directory. A full 40-character commit SHA is required; branches/tags are rejected.
All downloads and Bash syntax checks must succeed before files become executable.
No existing scripts are overwritten. Default never executes downloaded code.
--baseline explicitly runs the downloaded verifier as root after confirmation.
Download 06-hunt.sh separately until its pull request has been merged.
EOF
}
REF='' BASELINE=0
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
while (($#)); do
  case $1 in
    --help|-h) usage; exit 0 ;;
    --ref) (($# >= 2)) || die '--ref needs a commit SHA'; REF=$2; shift ;;
    --baseline) BASELINE=1 ;;
    *) die "unknown option: $1" ;;
  esac; shift
done
[[ $REF =~ ^[0-9a-fA-F]{40}$ ]] || die '--ref requires a full 40-character commit SHA'
if ((BASELINE)); then
  ((EUID == 0)) && [[ -t 0 && -t 1 ]] || die '--baseline requires root and an interactive terminal'
fi
for tool in curl bash mktemp chmod mv; do command -v "$tool" >/dev/null || die "$tool unavailable"; done
umask 077
destination=$(mktemp -d "./ccdc-${REF:0:12}.XXXXXXXX")
printf 'Downloading into %s\n' "$destination"
trap 'printf "Download incomplete; do not execute files in %s\n" "$destination" >&2' ERR
printf '%s\n' "$REF" > "$destination/INCOMPLETE"
BASE="https://raw.githubusercontent.com/CalebG1122/CCDC-SCRIPTS/$REF"
files=(01-users.sh 02-services.sh 03-firewall.sh 04-verify.sh)
for file in "${files[@]}"; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 120 "$BASE/$file" -o "$destination/$file.download"
  [[ -s $destination/$file.download ]] || { printf 'Empty download: %s\n' "$file" >&2; exit 1; }
  bash -n -- "$destination/$file.download"
done
# All files validated before the first executable permission is granted.
for file in "${files[@]}"; do
  mv -- "$destination/$file.download" "$destination/$file"
  chmod 700 "$destination/$file"
done
mv -- "$destination/INCOMPLETE" "$destination/COMMIT"
trap - ERR
printf 'Downloads validated. Review code before running: %s\n' "$destination"
if ((BASELINE)); then
  printf 'Type baseline to execute the downloaded verifier and save sensitive output: '
  IFS= read -r answer || exit 0
  [[ $answer == baseline ]] || exit 0
  code=0
  bash "$destination/04-verify.sh" > "$destination/baseline.txt" 2>&1 || code=$?
  printf 'Baseline saved to %s/baseline.txt; verifier status=%s\n' "$destination" "$code"
  exit "$code"
fi
