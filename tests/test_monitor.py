import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("monitor", Path(__file__).parents[1] / "scripts/monitor.py")
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


class MonitorTest(unittest.TestCase):
    def test_disabled_batch_does_not_run_any_checks(self):
        with patch.object(monitor, "run") as run:
            self.assertEqual([], monitor.collect([]))
            run.assert_not_called()

    def test_invalid_address_never_reaches_a_subprocess(self):
        with patch.object(monitor, "run") as run:
            data = monitor.check({"id": 1, "host": "--help; curl example.test"})
            self.assertEqual("failed", data["ssh"]["status"])
            run.assert_not_called()

    def test_root_and_shell_injection_user_are_rejected(self):
        with patch.object(monitor, "run") as run:
            for user in ("root", "name;id", "-oProxyCommand=id"):
                self.assertEqual("failed", monitor.ssh({"ssh_username": user}, "192.0.2.1")["status"])
            run.assert_not_called()

    def test_ssh_only_uses_publickey_and_fixed_read_only_command(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(monitor, "Path", return_value=Path(directory)), patch.object(monitor, "run", return_value=subprocess.CompletedProcess([], 0, "Model: mx204\nJunos: test", "")) as run:
                reply = monitor.ssh({"ssh_username": "ispsupport", "os_name": "Junos"}, "192.0.2.1")
                args = run.call_args.args[0]
                self.assertEqual("ok", reply["status"])
                self.assertIn("PreferredAuthentications=publickey", args)
                self.assertIn("StrictHostKeyChecking=accept-new", args)
                self.assertEqual("show version | no-more", args[-1])

    def test_snmp_secret_never_appears_in_arguments_and_file_is_private(self):
        secret = 'sample "community" with spaces'
        config_file = None
        def check_run(args, timeout, **kwargs):
            nonlocal config_file
            self.assertNotIn(secret, " ".join(args))
            config_file = Path(kwargs["env"]["SNMPCONFPATH"]) / "snmp.conf"
            self.assertEqual(0o600, config_file.stat().st_mode & 0o777)
            self.assertIn('defCommunity "sample \\"community\\" with spaces"', config_file.read_text())
            return subprocess.CompletedProcess(args, 0, "description " + secret, "")
        with patch.object(monitor.shutil, "which", return_value="/usr/bin/snmpget"), patch.object(monitor, "run", side_effect=check_run):
            value = monitor.snmp({"snmp_community": secret}, "192.0.2.1")
            self.assertEqual("ok", value["status"])
            self.assertNotIn(secret, str(value))
            self.assertFalse(config_file.exists())

    def test_missing_community_does_not_probe_snmp(self):
        with patch.object(monitor, "run") as run:
            self.assertEqual("skipped", monitor.snmp({}, "192.0.2.1")["status"])
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
