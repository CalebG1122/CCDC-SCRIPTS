#!/bin/bash
# get.sh - downloads the CCDC scripts from GitHub, makes them runnable, takes a baseline.
# Change YOURUSER to your GitHub username before uploading.
BASE="https://raw.githubusercontent.com/CalebG1122/CCDC-SCRIPTS/main"
for f in 01-users.sh 02-services.sh 03-firewall.sh 04-verify.sh; do
  curl -fsSL "$BASE/$f" -o "$f" && chmod +x "$f" && echo "got $f"
done
./04-verify.sh | tee ~/baseline.txt | less
