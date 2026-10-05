import argparse
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import contextmanager
from unittest.mock import patch

SOURCE = Path(__file__).parents[1] / 'scripts/pppoe_test.py'
spec = importlib.util.spec_from_file_location('bras_test', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

LINK = {'ifindex': 3, 'ifname': 'eth1', 'flags': ['UP', 'LOWER_UP'],
        'mtu': 1500, 'link_type': 'ether', 'address': '02:00:00:00:00:01'}
ADDRS = [{'family': 'inet6', 'scope': 'link', 'local': 'fe80::1', 'prefixlen': 64}]


class FakeNode:
    """Models commands, not a kernel: verifies scope, lifecycle and decisions."""
    def __init__(self, test, *, authfail=False, no_dns=False, http=200, loss=False):
        self.test = test
        self.authfail, self.no_dns, self.http, self.loss = authfail, no_dns, http, loss
        self.calls = []
        self.moved = False
        self.namespace = False
        self.proc = None
        self.start_count = 0

    def command(self, args, timeout=12, check=True):
        args = list(map(str, args))
        self.calls.append(args)
        if args[:3] == ['ip', 'netns', 'add']:
            self.namespace = True
        elif args[:3] == ['ip', 'netns', 'del']:
            self.namespace = False
        elif args[:3] == ['ip', 'netns', 'pids']:
            return 0, ''
        elif args[:4] == ['ip', 'link', 'set', 'eth1'] and 'netns' in args:
            self.moved = True
        elif args[:3] == ['ip', '-n', self.test.ns]:
            if args[3:8] == ['link', 'set', 'eth1', 'netns', str(m.os.getpid())]:
                self.moved = False
            elif args[3:7] == ['link', 'show', 'dev', 'eth1']:
                return (0, '') if self.moved else (1, 'missing')
            elif args[3:6] == ['-j', '-4', 'address']:
                return 0, json.dumps([{'ifname': self.test.ppp, 'mtu': 1492,
                    'flags': ['UP', 'POINTOPOINT'], 'addr_info': [{'family': 'inet', 'local': '100.64.0.2', 'prefixlen': 32}]}])
            elif args[3:6] == ['-j', '-4', 'route']:
                return 0, json.dumps([{'dst': 'default', 'dev': self.test.ppp}])
        elif args[0] == 'stat':
            st = Path(args[-1]).stat()
            return 0, '{}:{}\n'.format(st.st_dev, st.st_ino)
        elif args[:4] == ['ip', 'netns', 'exec', self.test.ns]:
            inner = args[4:]
            if inner[0] == 'stat':
                st = (self.test.etc / inner[-1].removeprefix('/etc/')).stat()
                return 0, '{}:{}\n'.format(st.st_dev, st.st_ino)
            if inner[0] == 'ping':
                loss = '20' if self.loss else '0'
                return 0, '5 packets transmitted, 5 received, {}% packet loss\nrtt min/avg/max/mdev = 1.0/2.0/3.0/0.1 ms\n'.format(loss)
            if inner[0] == 'dig':
                if '+short' in inner:
                    return 0, '203.0.113.17\n'
                return 0, ';; ->>HEADER<<- opcode: QUERY, status: NOERROR\nwww.yandex.ru. 20 IN A 203.0.113.17\n'
            if inner[0] == 'curl':
                # Exercise explicit resolution for the redirected host too.
                if inner[-1] == 'https://www.yandex.ru/':
                    return 0, 'http_code=302\nremote_ip=203.0.113.17\nbytes=10\ntotal_s=0.1\nredirect_url=https://yandex.ru/\n'
                return 0, 'http_code={}\nremote_ip=203.0.113.17\nbytes=1000\ntotal_s=0.2\nredirect_url=\n'.format(self.http)
        return 0, ''

    def ipjson(self, *args):
        if 'link' in args:
            return [copy.deepcopy(LINK)]
        if 'address' in args:
            return [{'addr_info': copy.deepcopy(ADDRS)}]
        if 'rule' in args:
            return [{'priority': 32766, 'table': 'main'}]
        if '-4' in args:
            return [{'dst': 'default', 'gateway': '192.0.2.1', 'dev': 'eth0'}]
        return [{'dst': 'fe80::/64', 'dev': 'eth1'}]

    def popen(self, args, **kwargs):
        assert args == ['ip', 'netns', 'exec', self.test.ns, 'pppd']
        test, node = self.test, self
        self.calls.append(args)
        self.start_count += 1
        peer = {'DNS1': None if self.no_dns else '192.0.2.53', 'DNS2': None, 'MACREMOTE': '00:11:22:33:44:55'}
        (test.etc / 'ppp/peer.json').write_text(json.dumps(peer))
        kwargs['stdout'].write('PAP authentication failed\n' if self.authfail else 'Connected to 00:11:22:33:44:55 via eth1\n')
        kwargs['stdout'].flush()
        class Process:
            returncode = 19 if node.authfail else None
            def poll(self): return self.returncode
            def terminate(self): self.returncode = 0
            def wait(self, **kw): return self.returncode
            def kill(self): self.returncode = -9
        self.proc = Process()
        return self.proc


class Tests(unittest.TestCase):
    def arguments(self, root):
        return argparse.Namespace(interface='eth1', bras='lab', output=str(root / 'report'),
            vlan=None, service='', ac='', expect_mac=LINK['address'], ping=['8.8.4.4', '8.8.8.8', '77.88.8.8'],
            namespace=None, hold=False, skip_initial_tests=False)

    @contextmanager
    def held_session(self, *, skip=True, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = self.arguments(root)
            a.hold, a.skip_initial_tests, a.namespace = True, skip, 'isp-pppoe-lab'
            before = {'link': copy.deepcopy(LINK), 'addresses': copy.deepcopy(ADDRS),
                      'sysctls': {}, 'pppd': 'pppd version 2.4.9', 'plugin': '/usr/lib/pppd/2.4.9/pppoe.so'}
            t = m.Test(a, before)
            t.etc = root / 'isolated-etc'
            node = FakeNode(t, **kwargs)
            with patch.object(m, 'command', node.command), patch.object(m, 'ipjson', node.ipjson), patch.object(m.subprocess, 'Popen', node.popen):
                t.prepare('test-login', 'test-secret')
                try:
                    yield t, node
                finally:
                    self.assertEqual(t.cleanup(), [])
                    self.assertFalse(node.moved)
                    self.assertFalse(node.namespace)
                    self.assertTrue(t.report['host_routes_rules_dns_unchanged'])

    def test_hold_idle_and_operator_stop_restore_interface(self):
        with self.held_session() as (t, node):
            options = (t.etc / 'ppp/options').read_text()
            self.assertIn('\nmaxconnect 0\n', options)
            self.assertIn('\nidle 0\n', options)
            self.assertIn('\nnopersist\n', options)
            sleeps = []
            def stop_after_two_polls(seconds):
                sleeps.append(seconds)
                self.assertEqual(json.loads((t.out / 'result.json').read_text())['status'], 'HOLDING')
                if len(sleeps) == 2:
                    raise KeyboardInterrupt('operator stop')
            with patch.object(m.time, 'sleep', side_effect=stop_after_two_polls):
                with self.assertRaises(KeyboardInterrupt):
                    t.hold()
            self.assertEqual(sleeps, [5, 5])
            self.assertFalse(any('ping' in c or 'dig' in c or 'curl' in c for c in node.calls))
            self.assertEqual(node.start_count, 1)

    def test_hold_disconnect_is_recorded_without_reconnect(self):
        with self.held_session() as (t, node):
            def disconnect(seconds): node.proc.returncode = 16
            with patch.object(m.time, 'sleep', side_effect=disconnect):
                self.assertEqual(t.hold(), 2)
            self.assertEqual(t.report['status'], 'SESSION_DOWN')
            self.assertEqual(t.report['pppd_exit_code'], 16)
            self.assertFalse(t.report['ipv4_available'])
            self.assertEqual(node.start_count, 1)
            events = [json.loads(line) for line in (t.out / 'events.jsonl').read_text().splitlines()]
            self.assertFalse(events[-1]['reconnect'])

    def test_initial_tests_and_manual_probe_keep_same_session(self):
        with self.held_session(skip=False) as (t, node):
            calls = []
            def signal_then_stop(seconds):
                calls.append(seconds)
                if len(calls) == 1:
                    self.assertEqual(t.report['last_test']['status'], 'PASS')
                    t.probe_requested = True
                else:
                    raise KeyboardInterrupt()
            with patch.object(m.time, 'sleep', side_effect=signal_then_stop):
                with self.assertRaises(KeyboardInterrupt): t.hold()
            self.assertEqual(t.probe_number, 2)
            self.assertEqual(node.start_count, 1)
            for number in (1, 2):
                report = json.loads((t.out / ('probe-{:04d}.json'.format(number))).read_text())
                self.assertEqual(report['status'], 'PASS')
                self.assertEqual(len(report['checks']['https_yandex']['hops']), 2)
            for c in node.calls:
                if any(x in c for x in ('curl', 'dig', 'ping', 'pppd')):
                    self.assertEqual(c[:4], ['ip', 'netns', 'exec', t.ns])
                if 'route' in c and ('add' in c or 'replace' in c):
                    self.assertEqual(c[:3], ['ip', '-n', t.ns])

    def test_failed_connectivity_does_not_disconnect_hold(self):
        with self.held_session(skip=False, http=403) as (t, node):
            with patch.object(m.time, 'sleep', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt): t.hold()
            self.assertEqual(t.report['status'], 'HOLDING')
            self.assertEqual(t.report['last_test']['status'], 'DEGRADED')
            self.assertIsNone(node.proc.poll())

    def test_short_ipcp_flaps_from_hooks_are_preserved(self):
        with self.held_session() as (t, node):
            # Execute the actual generated Python hooks, redirecting their
            # private /etc/ppp file paths into the fixture's isolated directory.
            for name in ('ip-up', 'ip-down', 'ip-up'):
                code = (t.etc / 'ppp' / name).read_text().replace('/etc/ppp/', str(t.etc / 'ppp') + '/')
                with patch.dict(m.os.environ, {'IPLOCAL': '100.64.0.2', 'IFNAME': t.ppp}):
                    exec(compile(code, name, 'exec'), {})
            self.assertTrue(t.read_hook_events())
            self.assertEqual(t.report['ipcp_up_events'], 2)
            self.assertEqual(t.report['ipcp_down_events'], 1)
            self.assertFalse(t.read_hook_events())
            self.assertEqual(t.report['ipcp_up_events'], 2)

    def test_existing_namespace_configuration_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            t = m.Test(self.arguments(root), {'link': LINK, 'pppd': '2.4.9'})
            t.etc = root / 'existing-etc'
            t.etc.mkdir()
            keep = t.etc / 'keep'
            keep.write_text('owned by another session')
            with self.assertRaisesRegex(RuntimeError, 'already exists'):
                t.prepare('user', 'secret')
            with patch.object(m, 'command') as commands:
                self.assertEqual(t.cleanup(), [])
                commands.assert_not_called()
            self.assertEqual(keep.read_text(), 'owned by another session')

    def scenario(self, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = self.arguments(root)
            before = {'link': copy.deepcopy(LINK), 'addresses': copy.deepcopy(ADDRS),
                      'sysctls': {}, 'pppd': 'pppd version 2.4.9', 'plugin': '/usr/lib/pppd/2.4.9/rp-pppoe.so'}
            t = m.Test(a, before)
            t.etc = root / 'isolated-etc'
            node = FakeNode(t, **kwargs)
            with patch.object(m, 'command', node.command), patch.object(m, 'ipjson', node.ipjson), patch.object(m.subprocess, 'Popen', node.popen):
                t.prepare('test-login', 'quoted"\\#secret')
                options = (t.etc / 'ppp/options').read_text()
                self.assertIn('nodefaultroute\n', options)
                self.assertIn('nopersist\n', options)
                self.assertNotIn('debug\n', options)
                if kwargs.get('authfail'):
                    with self.assertRaisesRegex(RuntimeError, 'pppd exited'):
                        t.exercise()
                    rc = 2
                else:
                    rc = t.exercise()
                self.assertEqual(t.cleanup(), [])
                t.log_summary()
            self.assertFalse(node.moved)
            self.assertFalse(node.namespace)
            self.assertFalse(t.etc.exists())
            self.assertTrue(t.report['host_routes_rules_dns_unchanged'])
            self.assertTrue(t.report['interface_restored'])
            for c in node.calls:
                self.assertNotIn('quoted"\\#secret', ' '.join(c))
                if any(x in c for x in ('curl', 'dig', 'ping', 'pppd')):
                    self.assertEqual(c[:4], ['ip', 'netns', 'exec', t.ns])
                if 'route' in c and 'add' in c:
                    self.assertEqual(c[:3], ['ip', '-n', t.ns])
                if 'curl' in c:
                    self.assertIn('--resolve', c)
                    self.assertIn('--noproxy', c)
                    self.assertNotIn('--location', c)
            self.assertNotIn('quoted', json.dumps(t.report))
            self.assertEqual(t.report.get('observed_ac_mac'), None if kwargs.get('authfail') else '00:11:22:33:44:55')
            return rc, t.report

    def test_success_and_redirect_isolation(self):
        rc, report = self.scenario()
        self.assertEqual(rc, 0)
        self.assertEqual(report['status'], 'PASS')
        self.assertFalse(report['identity_verified'])
        self.assertEqual(len(report['checks']['https_yandex']['hops']), 2)

    def test_auth_failure_restores_nic(self):
        rc, report = self.scenario(authfail=True)
        self.assertEqual(rc, 2)
        self.assertEqual(report['failure_stage'], 'AUTHENTICATION')

    def test_missing_peer_dns_is_not_green(self):
        rc, report = self.scenario(no_dns=True)
        self.assertEqual(rc, 1)
        self.assertEqual(report['dns_source'], 'public_fallback')

    def test_http_403_is_not_success(self):
        rc, report = self.scenario(http=403)
        self.assertEqual(rc, 1)
        self.assertFalse(report['checks']['https_yandex']['ok'])

    def test_ping_loss_is_not_success(self):
        rc, report = self.scenario(loss=True)
        self.assertEqual(rc, 1)
        self.assertEqual(report['checks']['ping_8.8.4.4']['loss_percent'], 20)

    def test_refuse_management_addresses_and_masters(self):
        cases = [({'family': 'inet', 'local': '192.0.2.3', 'prefixlen': 24, 'scope': 'global'}, None),
                 ({'family': 'inet6', 'local': '2001:db8::1', 'prefixlen': 64, 'scope': 'global'}, None),
                 (ADDRS[0], 'br0')]
        for address, master in cases:
            with self.subTest(address=address, master=master), tempfile.TemporaryDirectory() as tmp:
                link = copy.deepcopy(LINK)
                if master: link['master'] = master
                def fake_json(*args):
                    return [link] if 'link' in args else [{'addr_info': [address]}]
                with patch.object(m.shutil, 'which', return_value='/fake'), patch.object(m, 'ipjson', fake_json):
                    with self.assertRaisesRegex(RuntimeError, 'IP address|master'):
                        m.preflight(self.arguments(Path(tmp)))

    def test_options_cannot_inject_lines(self):
        with self.assertRaises(ValueError):
            m.quote_option('password\nconnect /danger')
        self.assertEqual(m.quote_option('a"\\b'), '"a\\"\\\\b"')

    def test_existing_report_dir_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = self.arguments(Path(tmp))
            Path(a.output).mkdir()
            keep = Path(a.output) / 'result.json'
            keep.write_text('existing report')
            t = m.Test(a, {'link': LINK, 'pppd': '2.4.9'})
            with self.assertRaises(FileExistsError): t.prepare('user', 'secret')
            self.assertFalse(t.out_created)
            self.assertEqual(keep.read_text(), 'existing report')


if __name__ == '__main__':
    unittest.main(verbosity=2)
