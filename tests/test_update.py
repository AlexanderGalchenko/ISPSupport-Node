import importlib.util
from pathlib import Path
import json
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("node_update", Path(__file__).parents[1] / "scripts/update.py")
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class UpdateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.source, self.node = root / "origin", root / "node"
        self.state = root / "state/update.json"
        self.source.mkdir()
        self.run_git(self.source, "init", "-b", "main")
        self.configure(self.source)
        (self.source / "README.md").write_text("one\n")
        self.commit(self.source, "initial")
        self.run_git(root, "clone", str(self.source), str(self.node))
        self.configure(self.node)

    def run_git(self, path, *args):
        return subprocess.check_output(["git", "-C", str(path), *args], stderr=subprocess.DEVNULL, text=True).strip()

    def configure(self, path):
        self.run_git(path, "config", "user.name", "test")
        self.run_git(path, "config", "user.email", "test@example.invalid")

    def commit(self, path, message):
        self.run_git(path, "add", ".")
        self.run_git(path, "commit", "-m", message)

    def update(self):
        return updater.update(self.node, self.state, str(self.source))

    def test_applies_new_commit_and_second_run_is_idempotent(self):
        (self.source / "README.md").write_text("two\n")
        self.commit(self.source, "next")
        self.assertEqual(self.update(), 0)
        self.assertEqual((self.node / "README.md").read_text(), "two\n")
        self.assertEqual(json.loads(self.state.read_text())["status"], "updated")
        self.assertEqual(self.update(), 0)
        self.assertEqual(json.loads(self.state.read_text())["status"], "unchanged")

    def test_preserves_local_changes(self):
        (self.node / "README.md").write_text("local\n")
        self.assertEqual(self.update(), 1)
        self.assertEqual((self.node / "README.md").read_text(), "local\n")

    def test_rejects_diverged_history(self):
        (self.node / "local.txt").write_text("local")
        self.commit(self.node, "local")
        before = self.run_git(self.node, "rev-parse", "HEAD")
        (self.source / "remote.txt").write_text("remote")
        self.commit(self.source, "remote")
        self.assertEqual(self.update(), 1)
        self.assertEqual(self.run_git(self.node, "rev-parse", "HEAD"), before)

    def test_fetch_failure_is_reported_without_changing_code(self):
        subprocess.check_call(["mv", str(self.source), str(self.source) + "-gone"])
        before = self.run_git(self.node, "rev-parse", "HEAD")
        self.assertEqual(self.update(), 1)
        self.assertEqual(json.loads(self.state.read_text())["status"], "failed")
        self.assertEqual(self.run_git(self.node, "rev-parse", "HEAD"), before)


if __name__ == "__main__":
    unittest.main()
