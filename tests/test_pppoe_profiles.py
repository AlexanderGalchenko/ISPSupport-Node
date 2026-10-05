import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('pppoe', Path(__file__).parents[1] / 'scripts/pppoe.py')
pppoe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pppoe)


class ProfileTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.profile = {'schema': 1, 'interface': 'eth1', 'expected_mac': '02:00:00:00:00:01',
                        'bras_label': 'lab', 'bras_address': '192.0.2.10', 'bras_port': 'et-0/0/0.123',
                        'vlan': None, 'transport_vlan': 123, 'ac': 'LAB_AC', 'note': 'declared mapping'}
        self.file = self.root / 'lab.json'
        self.addCleanup(patch.stopall)
        patch.object(pppoe, 'CONFIG', self.root).start()
        # Tests work without root; permission enforcement has a separate test.
        patch.object(pppoe, 'private_file').start()

    def load(self):
        self.file.write_text(json.dumps(self.profile))
        return pppoe.load_profile('lab')

    def test_transport_vlan_is_inventory_not_guest_tag(self):
        profile = self.load()
        args = pppoe.arguments('lab', profile, output='/reports/run')
        self.assertIn('--untagged', args)
        self.assertNotIn('--vlan', args)
        self.assertIn('--hold', args)
        self.assertNotIn('env_file', pppoe.binding(profile))

    def test_guest_vlan_is_explicit(self):
        self.profile['vlan'] = 456
        args = pppoe.arguments('lab', self.load(), output='/reports/run')
        self.assertEqual(args[args.index('--vlan') + 1], '456')
        self.assertNotIn('--untagged', args)

    def test_missing_vlan_and_unexpected_fields_fail_closed(self):
        del self.profile['vlan']
        with self.assertRaisesRegex(ValueError, 'Set vlan'):
            self.load()
        self.profile['vlan'] = None
        self.profile['PPPOE_PASSWORD'] = 'example-secret'
        with self.assertRaisesRegex(ValueError, 'Unknown profile fields'):
            self.load()

    def test_profile_name_and_credential_path_cannot_escape(self):
        for bad in ('../lab', '-lab', 'lab;touch x', '', None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                pppoe.name(bad)
        self.profile['env_file'] = '/root/.env'
        with self.assertRaisesRegex(ValueError, 'env_file'):
            self.load()

    def test_invalid_inputs_rejected_before_network_commands(self):
        for key, bad in [('vlan', True), ('vlan', 4095), ('expected_mac', 'anything'),
                         ('ping', ['--help']), ('ac', 'name\ninjected'), ('device_id', -1),
                         ('skip_initial_tests', 'false')]:
            with self.subTest(key=key):
                original = self.profile.copy()
                self.profile[key] = bad
                with self.assertRaises(ValueError):
                    self.load()
                self.profile = original

    def test_probe_never_starts_or_signals_starting_failed_or_busy_session(self):
        for active, state in [(False, 'HOLDING'), (True, 'STARTED'), (True, 'CONNECTED'),
                              (True, 'TESTING'), (True, 'SESSION_DOWN')]:
            with self.subTest(state=state), patch.object(pppoe, 'status', return_value={
                    'active': active, 'session': {'status': state}}), patch.object(pppoe, 'run') as run:
                self.assertEqual(pppoe.probe('lab'), 0)
                run.assert_not_called()

    def test_probe_signals_only_main_process_of_named_unit(self):
        with patch.object(pppoe, 'status', return_value={'active': True, 'session': {'status': 'HOLDING'}}), \
                patch.object(pppoe, 'run') as run:
            pppoe.probe('lab')
            run.assert_called_once_with(['systemctl', 'kill', '--kill-who=main', '--signal=USR1',
                                         'ispsupport-pppoe@lab.service'])

    def test_stopped_service_cannot_appear_connected_from_old_report(self):
        self.load()
        with patch.object(pppoe, 'read_current', return_value=({}, {'status': 'HOLDING', 'ipv4_available': True})), \
                patch.object(pppoe, 'system_state', return_value={'ActiveState': 'failed'}):
            self.assertFalse(pppoe.status('lab')['connected'])

    def test_private_credentials_reject_symlinks_and_world_readable_files(self):
        patch.stopall()
        secret = self.root / 'lab.env'
        secret.write_text('example only')
        secret.chmod(0o644)
        with self.assertRaises(ValueError):
            pppoe.private_file(secret)
        secret.chmod(0o600)
        link = self.root / 'linked.env'
        link.symlink_to(secret)
        with self.assertRaises(ValueError):
            pppoe.private_file(link)


if __name__ == '__main__':
    unittest.main()
