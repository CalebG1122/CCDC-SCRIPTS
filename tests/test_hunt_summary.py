#!/usr/bin/env python3
"""Test hunter summary formatting without scanning the host or changing files."""
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
if not (ROOT / '06-hunt.sh').exists():
    ROOT = Path(__file__).resolve().parent


class Summary(unittest.TestCase):
    def test_templates_use_disk_inventory_and_instances_are_queried(self):
        source = (ROOT / '06-hunt.sh').read_text()
        block = source.split('# BEGIN SYSTEMD MANAGER CHECKS\n', 1)[1].split('# END SYSTEMD MANAGER CHECKS', 1)[0]
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            manager = directory / 'systemctl'
            manager.write_text('''#!/bin/bash
case " $* " in
  *' list-unit-files '*) printf 'systemd-fsck@.service static\\nuser@.service static\\nplain.service enabled\\nexample@.timer static\\nexample@.socket static\\n';;
  *' list-units '*) printf 'user@1000.service loaded active running\\nplain.service loaded active running\\n';;
  *' show '*)
    name=${!#}
    printf '%s\\n' "$name" >> "$QUERY_LOG"
    case $name in *@.service|*@.timer|*@.socket) printf 'invalid template query\\n' >&2; exit 1;; esac
    if [[ ${FAIL_SHOW:-0} == 1 && $name == plain.service ]]; then printf 'real query failure\\n' >&2; exit 1; fi
    printf 'Id=%s\\n' "$name";;
esac
''')
            manager.chmod(0o700)
            script = directory / 'test.sh'
            script.write_text('set -uo pipefail\nSTATUS=0\nwarn() { printf "INCOMPLETE: %s\\n" "$*" >&2; STATUS=1; }\n'
                              + f'export PATH={shlex.quote(str(directory))}:/usr/bin:/bin\n'
                              + block + '\nexit "$STATUS"\n')
            import os
            log = directory / 'queries'
            for fail in [False, True]:
                if log.exists(): log.unlink()
                result = subprocess.run(['/bin/bash', str(script)], env={**os.environ, 'QUERY_LOG': str(log), 'FAIL_SHOW': str(int(fail))},
                                        text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, int(fail), result.stderr)
                self.assertEqual(log.read_text().splitlines(), ['plain.service', 'user@1000.service'])
                self.assertNotIn('invalid template', result.stderr)
                self.assertIn('on disk instead of as runtime units: 4', result.stdout)
                if fail: self.assertIn('cannot inspect unit: plain.service', result.stderr)

    def test_summary_caps_details_and_preserves_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            tools = directory / 'tools'
            tools.mkdir()
            worker = tools / 'bash'
            worker.write_text('''#!/bin/bash
printf 'INCOMPLETE: fixture permission failure\\n' >&2
printf '== System cron ==\\n'
for ((i=0;i<500;i++)); do
  printf '[cron] /etc/cron.d/local-%s\\nREVIEW: package ownership absent or unavailable\\nSECRET-CONTENT\\n' "$i"
done
printf '== Accounts, UID 0, SSH authorization and user systemd persistence ==\\n'
printf 'root:uid=0:gid=0:home=/root:shell=/bin/bash\\nextra:uid=0:gid=0:home=/extra:shell=/bin/bash\\n'
printf '== at jobs ==\\nJob 12\\n'
printf '== Recent or hidden files ==\\nMatched 400 paths; printed at most 300.\\n'
exit 1
''')
            worker.chmod(0o700)
            script = directory / '06-hunt.sh'
            script.write_text((ROOT / '06-hunt.sh').read_text().replace(
                'export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C',
                f'export PATH={shlex.quote(str(tools))}:/usr/bin:/bin LC_ALL=C'))
            result = subprocess.run(['/bin/bash', str(script)], text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 1)
            self.assertIn('fixture permission failure', result.stderr)
            self.assertIn('Unowned/unknown-package files: 500', result.stdout)
            self.assertEqual(result.stdout.count('[cron]'), 5)
            self.assertNotIn('SECRET-CONTENT', result.stdout)
            self.assertIn('Extra local UID 0 accounts: 1', result.stdout)
            self.assertIn('Recent or hidden paths: 400', result.stdout)
            self.assertLessEqual(len(result.stdout.splitlines()), 15)


if __name__ == '__main__':
    unittest.main(verbosity=2)
