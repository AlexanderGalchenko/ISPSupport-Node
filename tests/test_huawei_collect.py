import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('huawei_collect', Path(__file__).parents[1] / 'scripts/huawei_collect.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

VSI = '''***VSI Name : example
 VSI ID : 100
 VSI State : up
 PW Signaling : ldp
 MTU : 2000
 *Peer Router ID : 192.0.2.2
 Session : down
 Negotiation-vc-id : 100
 VC Label : 101
 Interface Name : Vlanif100
 State : up
 **PW Information:
 *Peer Ip Address : 192.0.2.2
 PW State : down
 Local VC Label : 101
 Remote VC Label : 0
 OutInterface :
 Another Field : must not become an interface
'''
TRUNK = '''Eth-Trunk1's state information is:
Local:
WorkingMode: LACP
Operate status: up
Number Of Up Port In Trunk: 1
ActorPortName Status PortType
XGigabitEthernet0/0/1 Selected 10GE
XGigabitEthernet0/0/2 Unselect 10GE
Partner:
XGigabitEthernet0/0/1 Selected 10GE
'''
LDP = '192.0.2.2:0 Operational 9 Passive 0000:01:00 1/1\nTOTAL: 1 session(s) Found.'
MAC = '0011-2233-4455 -/example/- XGigabitEthernet0/0/1 dynamic\nTotal items displayed = 1'
VERSION = 'VRP (R) software, Version 5.170 (S6730 V200R022C00SPC500)\nHUAWEI S6730-H48X6C uptime is 1 week, 2 days'


class HuaweiCollectorTest(unittest.TestCase):
    def test_up_vsi_still_reports_failed_pw_and_inactive_trunk_members(self):
        report = collector.build_report({'display version': VERSION, 'display vsi verbose': VSI,
            'display mpls ldp session': LDP, 'display eth-trunk': TRUNK, 'display mac-address': MAC},
            '192.0.2.1', 'example')
        self.assertTrue(report['complete'])
        self.assertEqual(report['vsi'][0]['peers'][0]['out_interface'], '')
        self.assertEqual(len(report['trunks'][0]['members']), 2)
        self.assertEqual(report['macs'][0]['mac'], '00:11:22:33:44:55')
        self.assertEqual(report['macs'][0]['vsi'], 'example')
        self.assertEqual(report['findings'][0]['kind'], 'pw_down')
        self.assertTrue(report['findings'][0]['ldp_operational'])
        self.assertEqual(report['findings'][1]['kind'], 'trunk_inactive_members')

    def test_long_vsi_name_can_touch_the_learned_from_column(self):
        text = '0011-2233-4455 -/A_VERY_LONG_EXAMPLE_VSI_NAME_100/-100GE0/0/6 dynamic\nTotal items displayed = 1'
        rows = collector.parse_macs(text)
        self.assertEqual(rows[0]['vsi'], 'A_VERY_LONG_EXAMPLE_VSI_NAME_100')
        self.assertEqual(rows[0]['learned_from'], '100GE0/0/6')

    def test_empty_and_partial_responses_are_missing_not_zero(self):
        for parser, text in [(collector.parse_macs, MAC.replace('= 1', '= 2')),
                             (collector.parse_ldp, LDP.replace('1 session', '2 session')),
                             (collector.parse_trunks, TRUNK.replace('Trunk: 1', 'Trunk: 4')),
                             (collector.parse_vsi, ''), (collector.parse_version, 'Error: denied')]:
            with self.subTest(parser=parser.__name__), self.assertRaises(ValueError):
                parser(text)
        report = collector.build_report({}, '192.0.2.1', 'example')
        self.assertFalse(report['complete'])
        self.assertIsNone(report['macs'])
        self.assertEqual(len(report['collection_errors']), 5)
        self.assertEqual(collector.parse_macs('Total items displayed = 0'), [])

    def test_only_allowlisted_commands_can_reach_cli(self):
        for command in ['system-view', 'reset mac-address', 'display mac-address vsi x\nreboot',
                        'display mac-address; reboot', 'display current-configuration']:
            self.assertFalse(collector.permitted(command))
        self.assertTrue(collector.permitted('display mac-address vsi example-100'))

    def test_ssh_checks_host_identity_and_legacy_option_is_explicit(self):
        base = ('192.0.2.1', 'ispsupport', '/key', '/known_hosts')
        args = collector.ssh_arguments(*base)
        self.assertIn('StrictHostKeyChecking=yes', args)
        self.assertIn('PasswordAuthentication=no', args)
        self.assertNotIn('PubkeyAcceptedAlgorithms=+ssh-rsa', args)
        self.assertIn('PubkeyAcceptedAlgorithms=+ssh-rsa', collector.ssh_arguments(*base, legacy_rsa=True))
        self.assertFalse(any('HostkeyAlgorithms' in arg for arg in args))
        for host in ['-oProxyCommand=x', 'example;reboot', '192.0.2.1\n']:
            with self.assertRaises(ValueError):
                collector.ssh_arguments(host, *base[1:])

    def test_output_limit_stops_session_before_unbounded_capture(self):
        class FakeExpect:
            class TIMEOUT(Exception):
                pass
            class EOF(Exception):
                pass
        class Child:
            def read_nonblocking(self, *args, **kwargs):
                return 'x' * 100
        session = collector.HuaweiSession.__new__(collector.HuaweiSession)
        session.pexpect = FakeExpect
        session.child = Child()
        session.hostname = 'example'
        session.total = 0
        session.deadline = collector.time.monotonic() + 1
        with patch.object(collector, 'MAX_OUTPUT', 50), self.assertRaises(collector.CollectionError):
            session._read_prompt(1)

    def test_report_write_is_private_and_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text('previous')
            path.chmod(0o644)
            collector.private_json(path, {'complete': True})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text()), {'complete': True})


if __name__ == '__main__':
    unittest.main()
