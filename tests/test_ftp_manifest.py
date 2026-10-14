import hashlib
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from ftp_manifest import manifest


class ManifestTest(unittest.TestCase):
    def test_stalled_but_open_ftp_upload_is_not_exported(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            upload = root / 'upload.gz'
            upload.write_bytes(b'partial')
            os.utime(upload, (1000, 1000))
            child = subprocess.Popen([sys.executable, '-c',
                'import fcntl,sys; f=open(sys.argv[1],"r+"); fcntl.lockf(f,fcntl.LOCK_EX); print("ready",flush=True); sys.stdin.read()',
                str(upload)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            try:
                self.assertEqual('ready', child.stdout.readline().strip())
                result = manifest(root, now=2000)
                self.assertEqual([], result['files'])
                self.assertEqual(1, result['skipped_recent_or_changed'])
            finally:
                child.communicate('', timeout=5)
            self.assertEqual(1, len(manifest(root, now=2000)['files']))

    def test_only_stable_regular_files_are_exported_with_exact_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'conf').mkdir()
            stable = root / 'conf' / 'router config\n1.gz'
            stable.write_bytes(b'configuration\x00bytes')
            os.utime(stable, (1000, 1000))
            (root / 'conf' / 'new.gz').write_bytes(b'upload in progress')
            (root / 'conf' / 'link').symlink_to('/etc/passwd')
            os.mkfifo(root / 'pipe')
            result = manifest(root, now=2000)
            self.assertEqual(1, len(result['files']))
            self.assertEqual('conf/router config\n1.gz', result['files'][0]['path'])
            self.assertEqual(hashlib.sha256(stable.read_bytes()).hexdigest(), result['files'][0]['sha256'])
            self.assertEqual(1, result['skipped_recent_or_changed'])

    def test_missing_and_symlink_roots_fail_instead_of_becoming_empty_success(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for path in [root / 'missing', root / 'link']:
                if path.name == 'link':
                    path.symlink_to(root, target_is_directory=True)
                with self.assertRaises(RuntimeError):
                    manifest(path)


if __name__ == '__main__':
    unittest.main()
