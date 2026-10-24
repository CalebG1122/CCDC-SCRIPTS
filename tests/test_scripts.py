#!/usr/bin/env python3
"""Unprivileged regression tests: no live account, service or firewall changes."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ['01-users.sh', '02-services.sh', '03-firewall.sh', '04-verify.sh', 'get.sh']
FIXED_PATH = 'export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C'


def run(name, *args, cwd=None, env=None):
    return subprocess.run(['bash', str(ROOT / name), *args], cwd=cwd, env=env,
                          text=True, capture_output=True, timeout=15)


class Scripts(unittest.TestCase):
    def test_syntax_help_and_unknown_arguments(self):
        for name in SCRIPTS:
            with self.subTest(name=name):
                result = subprocess.run(['bash', '-n', str(ROOT / name)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(run(name, '--help').returncode, 0)
                self.assertEqual(run(name, '--bogus').returncode, 2)

    def test_account_restrictions_require_explicit_allowlists(self):
        for flag in ['--restrict-admins', '--restrict-logins', '--keep-admin', '--password']:
            self.assertEqual(run('01-users.sh', flag).returncode, 2)

    def test_ssh_service_guard(self):
        result = run('02-services.sh', '--no-ssh')
        self.assertEqual(result.returncode, 2)
        self.assertIn('console', result.stderr)
        result = run('02-services.sh', '--disable', '../../bad')
        self.assertEqual(result.returncode, 2)

    def test_firewall_address_validation_and_allowlist_plan(self):
        args = ['--verbose', '--management-source', '192.0.2.7/24', '--management-source', '2001:db8::/64',
                '--scoring-source', '198.51.100.10', '--ssh-port', '2222']
        result = run('03-firewall.sh', *args, env={**os.environ, 'SSH_CONNECTION': ''})
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = [shlex.split(line) for line in result.stdout.splitlines() if not line.startswith('#')]
        self.assertTrue(commands)
        for command in commands:
            self.assertIn(command[0], ['iptables', 'ip6tables'])
            if '-s' in command:
                source = command[command.index('-s') + 1]
                self.assertEqual(':' in source, command[0] == 'ip6tables')
            if '--dport' in command:
                self.assertIn('-s', command)
            if '--ctorigdstport' in command and '-s' in command:
                self.assertEqual(command[-1], 'RETURN')
        self.assertIn('192.0.2.0/24', result.stdout)
        self.assertIn('2222', result.stdout)
        self.assertNotIn('--dport 8089', result.stdout)
        self.assertIn('--ctorigdstport 8089 -j DROP', result.stdout)
        for extra in [['--ssh-port', '0'], ['--ssh-port', '65536'], ['--web-source', 'bad'],
                      ['--forwarder-source', '$(touch /tmp/should-not-exist)']]:
            self.assertEqual(run('03-firewall.sh', *args, *extra).returncode, 2)
        self.assertEqual(run('03-firewall.sh', '--management-source', '192.0.2.0/24').returncode, 2)

    def test_firewall_default_output_is_short(self):
        result = run('03-firewall.sh', '--management-source', '192.0.2.0/24', '--no-scoring',
                     env={**os.environ, 'SSH_CONNECTION': ''})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLessEqual(len(result.stdout.splitlines()), 9)
        self.assertNotIn(' -A ', result.stdout)
        self.assertIn('--verbose', result.stdout)

    def test_verifier_summary_preserves_errors_and_caps_listings(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            tools = directory / 'tools'
            tools.mkdir()
            # The outer script still parses its real options and runs its real
            # summary. Only its recursive verbose scan is replaced with a fixture.
            worker = tools / 'bash'
            worker.write_text('''#!/bin/bash
printf 'INCOMPLETE: fixture check failed\\n' >&2
printf '\\n===== UID 0 accounts =====\\nroot:0:/root:/bin/bash\\nextra:0:/extra:/bin/bash\\n'
printf '\\n===== Local users and shells =====\\nroot -> /bin/bash\\n'
printf '\\n===== Listening ports =====\\n'
for ((i=0;i<100;i++)); do printf 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* SECRET-FIXTURE\\n'; done
printf '\\n===== sudoers standard paths (custom includes need manual follow-up) =====\\nKEY-CONTENT-SECRET\\n'
exit 1
''')
            worker.chmod(0o700)
            script = directory / '04-verify.sh'
            script.write_text((ROOT / '04-verify.sh').read_text().replace(FIXED_PATH,
                              f'export PATH={shlex.quote(str(tools))}:/usr/bin:/bin LC_ALL=C'))
            result = subprocess.run(['/bin/bash', str(script)], text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 1)
            self.assertIn('fixture check failed', result.stderr)
            self.assertIn('Extra UID 0 accounts: 1', result.stdout)
            self.assertIn('Listening sockets: 100', result.stdout)
            self.assertEqual(result.stdout.count('SECRET-FIXTURE'), 6)
            self.assertNotIn('KEY-CONTENT-SECRET', result.stdout)
            self.assertLessEqual(len(result.stdout.splitlines()), 16)

    def test_download_requires_immutable_commit(self):
        for value in ['', 'main', 'v1.0', '1234', 'g' * 40]:
            self.assertEqual(run('get.sh', '--ref', value).returncode, 2)

    def test_downloader_failure_never_runs_stale_verifier(self):
        self.check_download(fail=True)

    def test_downloader_success_stages_all_files_without_execution(self):
        self.check_download(fail=False)

    def check_download(self, fail):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            tools = directory / 'tools'
            tools.mkdir()
            fake_curl = tools / 'curl'
            fake_curl.write_text('''#!/bin/bash
set -eu
url='' target=''
while (($#)); do
  if [[ $1 == -o ]]; then target=$2; shift
  elif [[ $1 == https://* ]]; then url=$1; fi
  shift
done
printf '%s\\n' "$url" >> "$CALL_LOG"
if [[ ${FAIL_DOWNLOAD:-0} == 1 && $url == */02-services.sh ]]; then exit 22; fi
printf '#!/bin/bash\\nprintf executed >> "%s"\\n' "$EXEC_MARKER" > "$target"
''')
            fake_curl.chmod(0o700)
            # Only the test copy gets a fixture command path. Production has a fixed PATH.
            copy = directory / 'get.sh'
            copy.write_text((ROOT / 'get.sh').read_text().replace(FIXED_PATH,
                            f'export PATH={shlex.quote(str(tools))}:/usr/bin:/bin LC_ALL=C'))
            stale = directory / '04-verify.sh'
            stale.write_text('#!/bin/bash\nprintf stale > stale-ran\n')
            stale.chmod(0o700)
            env = {**os.environ, 'CALL_LOG': str(directory / 'calls'),
                   'EXEC_MARKER': str(directory / 'executed'), 'FAIL_DOWNLOAD': str(int(fail))}
            result = subprocess.run(['bash', str(copy), '--ref', 'a' * 40], cwd=directory,
                                    env=env, text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode == 0, not fail, result.stderr)
            self.assertFalse((directory / 'stale-ran').exists())
            self.assertFalse((directory / 'executed').exists())
            self.assertIn('stale', stale.read_text())
            stages = list(directory.glob('ccdc-*'))
            self.assertEqual(len(stages), 1)
            if fail:
                self.assertTrue((stages[0] / 'INCOMPLETE').exists())
                self.assertFalse(any(stages[0].glob('*.sh')))
            else:
                self.assertTrue((stages[0] / 'COMMIT').exists())
                self.assertEqual(len(list(stages[0].glob('*.sh'))), 4)
            self.assertIn('/' + 'a' * 40 + '/', (directory / 'calls').read_text())

    def test_rollback_restores_both_families_and_respects_commit_state(self):
        source = (ROOT / '03-firewall.sh').read_text()
        helper = source.split("<<'ROLLBACK'\n", 1)[1].split('\nROLLBACK\n', 1)[0]
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name in ['iptables-restore', 'ip6tables-restore']:
                tool = directory / name
                tool.write_text('''#!/bin/bash
printf '%s\\n' "${0##*/}" >> "$RESTORE_LOG"
cat >> "$RESTORE_LOG"
[[ ${FAIL_V6:-0} != 1 || ${0##*/} != ip6tables-restore ]]
''')
                tool.chmod(0o700)
            rollback = directory / 'rollback.sh'
            rollback.write_text(helper.replace(FIXED_PATH, f'export PATH={shlex.quote(str(directory))}:/usr/bin:/bin LC_ALL=C'))
            (directory / 'ipv4.rules').write_text('original-ipv4\n')
            (directory / 'ipv6.rules').write_text('original-ipv6\n')
            log = directory / 'restore.log'
            env = {**os.environ, 'RESTORE_LOG': str(log)}
            for state, fail_v6, expected, status in [('applied', False, 'restored', 0),
                                                      ('committed', False, 'committed', 0),
                                                      ('applied', True, 'restore-failed', 1)]:
                (directory / 'state').write_text(state + '\n')
                if log.exists(): log.unlink()
                result = subprocess.run(['bash', str(rollback)], env={**env, 'FAIL_V6': str(int(fail_v6))},
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual((directory / 'state').read_text().strip(), expected)
                if state == 'committed':
                    self.assertFalse(log.exists())
                else:
                    self.assertIn('original-ipv4', log.read_text())
                    self.assertIn('original-ipv6', log.read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
