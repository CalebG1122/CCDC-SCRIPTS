06-hunt.sh
==========
Requires Linux, Bash 4+, GNU coreutils and GNU findutils. Run from a trusted
administrative environment; root gives the most complete inventory.

Run:
  chmod 700 06-hunt.sh check-06-hunt.sh
  ./check-06-hunt.sh ./06-hunt.sh
  sudo ./06-hunt.sh
  sudo ./06-hunt.sh --since '2026-10-23 08:00' --root /etc --root /home
  sudo ./06-hunt.sh --clean

Dates without an explicit offset use the Linux host's local timezone.
Default mode creates no temporary files or other intentional filesystem writes.
Normal access-time updates, audit logging and command implementation behavior
are controlled by the OS. A forensic acquisition should use a read-only mount.
Output is sensitive: at job environments can contain credentials.

Interpretation:
- Package ownership is context, not an integrity check. Package-owned files may
  be altered; unowned local configurations are common and legitimate.
- Unit configuration includes disk files, drop-ins, enablement symlinks, runtime
  units, generators and user units. Effective system service commands are queried
  from systemd. User managers are not contacted or started: their on-disk files
  are inventoried. Other XDG search paths may require manual inspection.
- Review Exec*, EnvironmentFile, timer/socket targets and referenced scripts.
  The scanner never evaluates configuration or executes discovered commands.
- sudoers includes and SSH Match/Include/custom authorization paths outside the
  standard locations require manual follow-up. SSH key contents are not judged
  malicious. UID 0 root is expected. NSS enumeration may be incomplete.
- Recent/hidden searches stay on each root filesystem, with capped output.
  Add explicit roots for other mounts. Timestamps and hidden names prove nothing.
- This is a persistence inventory, not an exhaustive incident-response tool.
  Other mechanisms (shell startup, PAM, loaders, containers, etc.) are outside scope.

Cleanup:
Only unowned regular files directly inside the standard cron task directories
are offered. Every item requires typing its full path at /dev/tty. The tool
refuses symlinked paths, hard links, non-root-owned files and changed evidence.
No bulk yes option. No removal based on timestamps or hidden-file results.
Missing/unknown package ownership must be investigated before confirming.

After confirmation, /var/lib/06-hunt-backup.RANDOM is created privately. It holds
a verified metadata-preserving backup, original-path, and the quarantined original.
The original is moved out of cron; jobs already running are unaffected. No backup
is deleted. To restore, review original-path, verify the destination is absent,
and as root copy quarantined back with cp -a. Do not restore over an existing file.
Backups may contain secrets. Keep them private and retain them for investigation.
Do cleanup only while configuration is quiescent. Shell checks cannot prevent
all races, and the script cannot defend against a malicious root or kernel.

Validation in the authoring environment:
Both scripts passed a Tree-sitter Bash grammar parse with no error/missing nodes.
LF/UTF-8 encoding, required coverage and cleanup guard placement were checked.
The Windows sandbox blocked Git Bash and WSL; Docker had no running Linux engine.
Consequently bash -n and Linux runtime/interactive tests could not be executed
here. check-06-hunt.sh supplies syntax/help/invalid-argument checks for Linux.
Review and run these checks before use; test cleanup on a disposable Linux host.
